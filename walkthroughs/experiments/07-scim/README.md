# Experiment 7: SCIM Provisioning + Deprovisioning

Explore the full user lifecycle through SCIM (RFC 7644) — creating users with POST, surgical updates with PATCH, the data-loss danger of PUT, and the DELETE cascade that must happen in seconds, not minutes. See the revocation timing gap that CAEP closes.

## Layer

**Lifecycle** — How are identities created, updated, and destroyed? (SCIM, provisioning, deprovisioning)

## What you'll learn

- The SCIM User resource — every field in a POST /Users request and response
- Server-assigned fields: id, meta block (resourceType, created, lastModified, location, version/ETag)
- PATCH operations (replace, add, remove) with the PatchOp schema
- Why PUT replaces the entire resource and deletes missing fields
- The DELETE cascade: disable → revoke sessions → emit SET event → downstream kills sessions
- The revocation timing gap: minutes without CAEP, milliseconds with it
- SCIM vs JIT provisioning tradeoffs
- The full identity lifecycle from proofing through deprovisioning

## How to run

```bash
node run.js
```

Interactive mode steps through one screen at a time. Press ENTER to advance.

For a full dump (all scenarios, no pausing):

```bash
node run.js --no-pause
```

## Estimated time

~20 minutes

## After running, you should be able to:

- Explain what SCIM is and why it's needed (RFC 7644, push provisioning)
- Describe the difference between PATCH and PUT in SCIM (and why PUT is dangerous for partial updates)
- Walk through a proper DELETE cascade (4 steps)
- Explain the revocation timing gap and how CAEP closes it
- Compare SCIM vs JIT provisioning and when to use each
- Trace the full identity lifecycle across all experiments
