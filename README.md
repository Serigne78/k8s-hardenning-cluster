# Kubernetes Hardening Lab

End-to-end hardening of a single-node Kubernetes cluster against the **CIS Kubernetes Benchmark**, measured with kube-bench before and after each control. The goal of this lab is not only to reach a passing score, but to document *why* each control matters — the attack surface it closes and how the fix works under the hood.

## Environment

| Component | Version |
|-----------|---------|
| Kubernetes | v1.30.14 |
| OS | Ubuntu 24.04.4 LTS |
| CNI | Cilium (eBPF, kube-proxy replacement) |
| Container runtime | containerd 2.2.1 |
| Benchmark tool | kube-bench, profile CIS 1.10 |

## Results

| State | PASS | FAIL | WARN |
|-------|------|------|------|
| Before hardening | 62 | 10 | 56 |
| After hardening | 73 | 1* | 56 |

\* The single remaining FAIL (4.3.1) is a **documented false positive** — see the last section.

Full reports: [`report/`](report/).

---

## Controls applied

Each section follows the same structure: **what CIS checks**, **the risk if it's left open**, and **how I fixed it**.

### 1. API server audit logging — CIS 1.2.16 to 1.2.19

**What it checks:** whether the API server records who does what on the cluster.

**Risk:** without an audit log, there is no record of any action taken against the API server. If an attacker reads a secret, creates a privileged binding, or deploys a malicious pod, none of it is traceable. Detection and post-incident forensics become impossible.

**How I fixed it:** I wrote a multi-level audit policy ([`manifest/audit/audit-policy.yaml`](manifest/audit/audit-policy.yaml)) that logs by sensitivity rather than logging everything (which would flood the disk and drown the signal):

- **`RequestResponse`** on `secrets`, `configmaps` and all RBAC resources — the full request *and* response body is logged, so a secret read or a `ClusterRoleBinding` creation can be fully reconstructed.
- **`Request`** on workloads (`pods`, `deployments`, `daemonsets`) — the submitted manifest is captured, enough to see a malicious pod spec (e.g. `hostPID: true`, suspicious image).
- **`Metadata`** as the catch-all — who/what/when, without the payload.
- **`None`** on predictable system noise (kube-proxy watching endpoints, kubelet reading its own node) to keep the log readable.

Log rotation is configured on the API server flags: `--audit-log-maxage=30`, `--audit-log-maxbackup=10`, `--audit-log-maxsize=100`, capping audit logs at ~1.1 GB on disk.

### 2. Kubelet certificate authority verification — CIS 1.2.5

**What it checks:** whether the API server verifies the identity of the kubelet it talks to.

**Risk:** by default the API server trusts any process claiming to be a kubelet on port 10250. An attacker who has compromised a node can impersonate the kubelet and intercept traffic from the API server — including pod logs and `exec` sessions. This is a man-in-the-middle attack inside the cluster.

**How I fixed it:** I set `--kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt`. The API server now validates the kubelet's TLS certificate against the cluster CA before communicating. Because the CA's private key (`ca.key`) is required to produce a valid signature and never leaves the control plane, a forged kubelet certificate is rejected — the same trust model as HTTPS.

### 3. Profiling disabled — CIS 1.2.21, 1.3.2, 1.4.1

**What it checks:** whether the `/debug/pprof` endpoint is exposed on the API server, controller-manager and scheduler.

**Risk:** the profiling endpoint exposes live memory and CPU data and internal data structures. An attacker with access can map what's running, detect load patterns, and gather reconnaissance for a deeper attack.

**How I fixed it:** `--profiling=false` on all three control-plane components.

### 4. etcd data directory ownership — CIS 1.1.12

**What it checks:** ownership of the etcd data directory.

**Risk:** etcd stores the entire cluster state, including every secret and certificate in plaintext. If a non-root process can read `/var/lib/etcd`, it can extract every secret in the cluster.

**How I fixed it:** restricted ownership to `etcd:etcd`, so only the etcd process can read its own data.

### 5. Kubelet configuration file permissions — CIS 4.1.1, 4.1.9

**What it checks:** file permissions on the kubelet service and config files.

**Risk:** world-readable kubelet config can leak connection details and tokens.

**How I fixed it:** tightened permissions to `600` (owner read/write only) on the kubelet config files.

### 6. kube-proxy metrics exposure — CIS 4.3.1 (documented false positive)

**What it checks:** whether the kube-proxy metrics endpoint (port 10249) is bound to localhost rather than `0.0.0.0`.

**Analysis:** this cluster runs **Cilium in kube-proxy replacement mode**, so kube-proxy is not present at all. Querying the endpoint from the node's network address confirms nothing is listening:



### Pod Security Standards — restricted profile

**Risk:** without admission control, any user able to create a pod can run a
privileged container, mount the host filesystem, or share the host PID
namespace — a direct path to node compromise.

**Fix:** enforced the `restricted` Pod Security Standard at namespace level
(manifest/pod-security/). Three modes are set — `enforce` blocks, `warn`
messages the user, `audit` records to the audit log — which together allow a
safe migration on an existing cluster.

**Evidence:**
- A privileged pod is rejected at admission with 5 violations listed
  (report/pss-blocked-pod.txt).
- A compliant pod (runAsNonRoot, seccomp RuntimeDefault, all capabilities
  dropped) is admitted and runs.

Note: PSS validates the *declared* security context, not the image itself —
a pod declaring runAsNonRoot on a root image is admitted but fails at runtime
with CreateContainerConfigError. The compliant example uses nginx-unprivileged.

### Runtime threat detection — Falco

**Risk:** prevention controls (PSS, NetworkPolicies) stop bad configuration, but a compromised container that behaves maliciously at runtime — spawning a shell, reading credentials, launching a miner — passes them unnoticed. Detection is the layer that catches what prevention lets through.

**Implementation:** Falco deployed as a DaemonSet with a modern eBPF probe, capturing syscalls cluster-wide. Two things demonstrated:

1. **Default rules** — a `kubectl exec` shell and a read of `/etc/shadow` are both detected, with full process lineage (`cat` ← `bash` ← `containerd-shim`) and Kubernetes context (pod, namespace, image). See `report/falco-alerts.txt`.
2. **Custom rule** — a CRITICAL rule detecting known cryptominer binaries (xmrig, minerd, etc.) launched inside a container, n (`manifest/falco/custom-rules.yaml`).

**Known limitation:** name-based miner detection is evaded by renaming the binary. Behaviour-based detection (mining-pool connections, CPU anomalies) would be the production-grade follow-up.

### Network micro-segmentation — Cilium NetworkPolicies

**Risk:** by default, Kubernetes allows all pod-to-pod traffic. Any compromised
pod can reach every service in the cluster — unrestricted east-west movement,
the primary vector for lateral movement after an initial breach.

**Implementation:** a default-deny ingress policy closes all inbound traffic in
the namespace, then a single explicit rule re-opens only `frontend → backend`
on TCP/80, selected by pod label (manifest/network-policies/).

**Evidence (verified two ways):**

| Source | Destination | Result |
|--------|-------------|--------|
| frontend (app=frontend) | backend:80 | 200 — allowed |
| attacker (app=attacker) | backend:80 | 000 timeout — dropped |

Same destination, two verdicts, decided solely by pod label. Hubble confirms
the drop at the network layer (report/hubble-dropped.txt) — the UI shows the
attacker→backend link in red with every flow marked `dropped`.

**Key insight:** the Hubble UI draws attempted connections, not just successful
ones — a visible arrow is not proof of access. The verdict (FORWARDED vs
DROPPED) is what matters. Always cross-check the graph with `hubble observe --verdict.

<img width="1178" height="575" alt="Capture d&#39;écran 2026-09-11 000519" src="https://github.com/user-attachments/assets/dc037c97-4a86-4a99-bc1e-33f0bc763272" />

<img width="1918" height="945" alt="Capture d&#39;écran 2026-09-11 002037" src="https://github.com/user-attachments/assets/ca44bd5c-e590-4433-b56f-2ef14632e52e" />

<img width="1914" height="895" alt="Capture d&#39;écran 2026-09-11 002053" src="https://github.com/user-attachments/assets/638d3431-ef3d-459c-88e9-1898a47b9803" />



