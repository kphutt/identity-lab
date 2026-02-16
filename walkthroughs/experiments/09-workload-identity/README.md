# Experiment 9: Workload Identity Federation

Workload Identity Federation eliminates static secrets for machine-to-machine authentication. Workloads (pods, VMs, CI jobs) authenticate to cloud services using platform-native OIDC tokens — the same JWT format from Experiment 1, verified against JWKS from Experiment 6, exchanged via RFC 8693 token exchange.

## Layer

**Cross-cutting** — WIF ties the entire identity stack together: OIDC tokens, JWKS verification, token exchange, and lifecycle management across all layers.

## What you'll learn

- Workload Identity Federation (WIF) — how workloads authenticate without static secrets
- K8s projected ServiceAccount OIDC tokens — header (typ, alg, kid) and payload (iss, sub, aud, kubernetes.io claims)
- Token exchange (RFC 8693) — workload OIDC token to short-lived cloud access token via STS
- 5-step STS verification: signature against cluster JWKS, iss trust, sub allowlist, aud check, issue cloud token
- GCP WIF end-to-end flow: kubelet projects token, pod reads from volume mount, presents to STS
- SPIFFE/SVID — standard for workload identity (spiffe://trust-domain/path, JWT SVIDs)
- The Secret Zero problem and how WIF eliminates it
- Token lifetime comparison: 15-min auto-rotated workload tokens vs static API keys
- Static secrets vs WIF comparison (bootstrapping, rotation, blast radius, audit)
- Capstone connection map: all 9 experiments across the 5-layer stack model

## How to run

```bash
npm install
node run.js
```

Interactive mode steps through one screen at a time. Press ENTER to advance.

For a full dump (all scenarios, no pausing):

```bash
node run.js --no-pause
```

## Estimated time

~25 minutes

## After running, you should be able to:

- Explain what Workload Identity Federation is and why it eliminates static secrets
- Walk through the token exchange flow: workload OIDC token → STS verification → short-lived cloud token
- Describe the Secret Zero problem and how platform-attested identity solves it
- Explain SPIFFE IDs and SVIDs for platform-agnostic workload identity
- Compare short-lived auto-rotated workload tokens to static API keys
- Map how WIF connects all 9 experiments across the identity stack
