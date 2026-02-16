#!/usr/bin/env node

// Experiment 7: SCIM Provisioning + Deprovisioning
// Layer: Lifecycle
// Run: node run.js (interactive) or node run.js --no-pause (full dump)

import { randomBytes } from 'node:crypto';
import { createCLI } from '../../shared/cli.js';

const NO_PAUSE = process.argv.includes('--no-pause');
const { pause, explore, close } = createCLI({ noPause: NO_PAUSE });

// ── Main ────────────────────────────────────────────────────────

async function main() {
  // ── Pre-built Artifacts ─────────────────────────────────────
  const userId = 'user-' + randomBytes(4).toString('hex');
  const sessionId = 'sess-' + randomBytes(4).toString('hex');
  const jti = randomBytes(8).toString('hex');
  const now = Math.floor(Date.now() / 1000);
  const tokenTTL = 600; // 10 minutes

  // Full SCIM User resource
  const scimUser = {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: userId,
    externalId: 'emp-48201',
    userName: 'j.martinez@example.com',
    name: {
      givenName: 'Jordan',
      familyName: 'Martinez',
      formatted: 'Jordan Martinez',
    },
    emails: [
      { value: 'j.martinez@example.com', type: 'work', primary: true },
      { value: 'jordan.m@personal.com', type: 'home', primary: false },
    ],
    active: true,
    groups: [
      { value: 'grp-engineering', display: 'Engineering' },
      { value: 'grp-platform', display: 'Platform Team' },
    ],
    meta: {
      resourceType: 'User',
      created: new Date().toISOString(),
      lastModified: new Date().toISOString(),
      location: `https://scim.example.com/v2/Users/${userId}`,
      version: 'W/"v1"',
    },
  };

  // PatchOp object
  const patchOps = {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [
      { op: 'replace', path: 'active', value: false },
      { op: 'add', path: 'emails', value: [{ value: 'j.martinez@newdomain.com', type: 'work' }] },
    ],
  };

  // PUT body deliberately OMITTING emails and groups
  const putBody = {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    userName: 'j.martinez@example.com',
    name: {
      givenName: 'Jordan',
      familyName: 'Martinez',
      formatted: 'Jordan Martinez',
    },
    active: false,
  };

  // Decoded SET payload for DELETE cascade preview
  const setEventPayload = {
    iss: 'https://idp.example.com',
    iat: now,
    jti: jti,
    aud: 'https://api.example.com',
    events: {
      'https://schemas.openid.net/secevent/caep/event-type/session-revoked': {
        subject: {
          format: 'opaque',
          id: sessionId,
        },
        event_timestamp: now,
        reason_admin: {
          en: 'User deprovisioned via SCIM DELETE',
        },
      },
    },
  };

  // ── Title Card ──────────────────────────────────────────────

  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  Experiment 7: SCIM Provisioning + Deprovisioning               ║
║  Layer: Lifecycle                                                ║
║  Time: ~20 minutes                                               ║
║                                                                  ║
║  Step through with ENTER. Use --no-pause for full dump.          ║
╚══════════════════════════════════════════════════════════════════╝

  SCIM handles the full lifecycle — create, update, disable, delete.
  Get deprovisioning wrong and a terminated employee keeps access for
  minutes. This experiment covers the REST API that pushes user lifecycle
  events to downstream services, and the revocation timing gap that
  CAEP closes.

  Builds on: Experiment 1 (OIDC tokens, JWTs)
             Experiment 2 (DPoP, DBSC session binding)
             Experiment 3 (WebAuthn registration)
  Sets up:   Experiment 8 (CAEP — real-time revocation signals)
`);
  await pause();

  // ── STEP 1: POST /Users — Creating a User ─────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 1: POST /Users — Creating a User

  SCIM (System for Cross-domain Identity Management, RFC 7644) is a
  REST API for provisioning and deprovisioning user accounts. The IdP
  (or HR system) pushes user lifecycle events — create, update, disable,
  delete — to downstream services.

  POST https://scim.example.com/v2/Users
  Content-Type: application/scim+json

  {
    "schemas": ${JSON.stringify(scimUser.schemas)},
        ↳ Schema URIs identify the resource type. Extensions add their
          own URIs to this array. Every SCIM request declares which
          schemas it uses.

    "externalId": "${scimUser.externalId}",
        ↳ External ID. An identifier from the provisioning source (HR
          system, IdP). The SCIM server stores it but doesn't assign
          it — the client owns this value.

    "userName": "${scimUser.userName}",
        ↳ User Name. The unique identifier — often an email or employee
          ID. This is the login identity across systems.

    "name": {
      "givenName": "${scimUser.name.givenName}",
      "familyName": "${scimUser.name.familyName}",
      "formatted": "${scimUser.name.formatted}"
    },
        ↳ Name. Structured name with components. "formatted" is the
          display-ready full name. Some systems use givenName +
          familyName; others use formatted directly.

    "emails": [
      { "value": "${scimUser.emails[0].value}", "type": "work", "primary": true },
      { "value": "${scimUser.emails[1].value}", "type": "home", "primary": false }
    ],
        ↳ Emails. Array of email objects with type and primary flag.
          Multiple emails supported — "work", "home", etc. Only one
          can be primary:true. This matters for PATCH vs PUT later.

    "active": true,
        ↳ Active. Boolean. true = account enabled. false = disabled but
          NOT deleted — this is the soft-delete mechanism. Deprovisioning
          often sets active=false before hard DELETE.

    "groups": [
      { "value": "${scimUser.groups[0].value}", "display": "${scimUser.groups[0].display}" },
      { "value": "${scimUser.groups[1].value}", "display": "${scimUser.groups[1].display}" }
    ]
        ↳ Groups. The user's group memberships. Often read-only —
          managed via Group resources, not the User endpoint.
          "value" is the group ID, "display" is human-readable.
  }

  🎯 INTERVIEW ALERT: "What is SCIM and why is it needed?"
     SCIM (RFC 7644) is a REST API for pushing user lifecycle events
     to downstream services. Without it, each service needs custom
     provisioning integration. The IdP/HR system pushes create, update,
     and delete — services don't poll, they receive.
`);
  await pause();

  // ── STEP 2: SCIM Response ─────────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 2: SCIM Response — Server-Assigned Fields

  The SCIM server responds with the full resource, now including
  server-assigned fields: the internal id and the meta block.

  HTTP/1.1 201 Created
  Content-Type: application/scim+json
  Location: ${scimUser.meta.location}

  {
    "schemas": ${JSON.stringify(scimUser.schemas)},
    "id": "${scimUser.id}",
        ↳ Server-Assigned ID. The SCIM server generates this — it's
          the canonical identifier within this service. Different from
          externalId (which comes from the provisioning source).

    "externalId": "${scimUser.externalId}",
    "userName": "${scimUser.userName}",
    "name": { ... },
    "emails": [ ... ],
    "active": true,
    "groups": [ ... ],

    "meta": {
      "resourceType": "${scimUser.meta.resourceType}",
          ↳ Resource Type. "User", "Group", or an extension type.
            Tells the client what schema to expect.

      "created": "${scimUser.meta.created}",
          ↳ Created. Server timestamp of resource creation. ISO 8601.

      "lastModified": "${scimUser.meta.lastModified}",
          ↳ Last Modified. Updated on every change. Clients can use
            this for conditional requests (If-Modified-Since).

      "location": "${scimUser.meta.location}",
          ↳ Location. The canonical URL of this resource. Same as
            the Location header. Use this for subsequent GET/PATCH/
            PUT/DELETE operations.

      "version": "${scimUser.meta.version}"
          ↳ Version (ETag). Optimistic concurrency control. The client
            sends If-Match: ${scimUser.meta.version} on updates. If the
            resource changed since last read, the server returns 412
            Precondition Failed. Prevents lost updates when two admins
            modify the same user simultaneously.
    }
  }

  The meta block is read-only — the server manages these fields.
  The client never sets id, created, lastModified, or version.
`);
  await pause();

  // ── STEP 3: PATCH Operations ──────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 3: PATCH Operations — Surgical Updates

  SCIM PATCH uses a PatchOp schema with an Operations array. Each
  operation specifies exactly what to change — nothing else is touched.

  PATCH https://scim.example.com/v2/Users/${scimUser.id}
  Content-Type: application/scim+json

  {
    "schemas": ${JSON.stringify(patchOps.schemas)},
        ↳ The schema URI for PATCH operations. Required — this tells
          the server it's receiving a PatchOp, not a User resource.

    "Operations": [
        ↳ An array of operations to apply, in order.
      {
        "op": "replace",
            ↳ Operation type. Three options:
              "replace" — overwrite an existing field's value
              "add"     — create a field or append to an array
              "remove"  — delete a field or array element
              These are the only three. No "move" or "copy."

        "path": "active",
            ↳ Which attribute to modify. Dot notation for nested
              fields: "name.givenName". Can target array elements
              with filters: "emails[type eq \\"work\\"].value".

        "value": false
            ↳ The new value. For "replace", overwrites the field.
              For "add", creates the field or appends to arrays.
              For "remove", value is omitted.
      },
      {
        "op": "add",
        "path": "emails",
        "value": [{ "value": "j.martinez@newdomain.com", "type": "work" }]
            ↳ Adds to the emails array without replacing existing
              entries. The user now has 3 emails, not 1.
      }
    ]
  }

  Three operation types summarized:

  ┌───────────┬────────────────────────────────────────────────────┐
  │  replace  │  Overwrite a field. "active": true → false.        │
  │           │  If field doesn't exist, behaves like "add"       │
  │           │  (RFC 7644 §3.5.2.3).                             │
  ├───────────┼────────────────────────────────────────────────────┤
  │  add      │  Create a field or append to an array. Safe for   │
  │           │  both new and existing fields. Array values are    │
  │           │  appended, not replaced.                           │
  ├───────────┼────────────────────────────────────────────────────┤
  │  remove   │  Delete a field or array element. No "value"       │
  │           │  needed. Path required: "emails[type eq \\"home\\"]" │
  │           │  removes the home email without touching work.     │
  └───────────┴────────────────────────────────────────────────────┘
`);
  await pause();

  // ── STEP 4: Lifecycle Operations Lab (Exploration Point) ───

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 4: Lifecycle Operations Lab

  SCIM covers the full lifecycle — create, update, disable, delete.
  Each operation has different semantics and different risks. Let's
  explore what happens with each approach.`);

  await explore('Pick a scenario to explore:', [
    {
      name: 'PATCH (surgical update)',
      fn: async () => {
        console.log(`  PATCH — Surgical Update`);
        console.log();
        console.log(`  Apply the PatchOp: replace active=false, add a new email.`);
        console.log();
        console.log(`  BEFORE:                                     AFTER:`);
        console.log(`  ─────────────────────────────────            ─────────────────────────────────`);
        console.log(`  "userName": "${scimUser.userName}"     "userName": "${scimUser.userName}"`);
        console.log(`  "name": {                                    "name": {`);
        console.log(`    "givenName": "Jordan",                       "givenName": "Jordan",`);
        console.log(`    "familyName": "Martinez"                     "familyName": "Martinez"`);
        console.log(`  }                                            }`);
        console.log(`  "emails": [                                  "emails": [`);
        console.log(`    { "value": "j.martinez@example.com",         { "value": "j.martinez@example.com",`);
        console.log(`      "type": "work", "primary": true },          "type": "work", "primary": true },`);
        console.log(`    { "value": "jordan.m@personal.com",          { "value": "jordan.m@personal.com",`);
        console.log(`      "type": "home" }                             "type": "home" },`);
        console.log(`  ]                                              { "value": "j.martinez@newdomain.com",`);
        console.log(`                                                   "type": "work" }              ← added`);
        console.log(`                                                ]`);
        console.log(`  "active": true                               "active": false                   ← changed`);
        console.log(`  "groups": [                                  "groups": [`);
        console.log(`    { "display": "Engineering" },                { "display": "Engineering" },`);
        console.log(`    { "display": "Platform Team" }               { "display": "Platform Team" }`);
        console.log(`  ]                                            ]`);
        console.log();
        console.log(`  Only the specified fields changed. Everything else — userName, name,`);
        console.log(`  existing emails, groups — preserved exactly as-is.`);
        console.log();
        console.log(`  PATCH is the safe update method for partial modifications.`);
      },
    },
    {
      name: 'PUT (full replace — data loss)',
      fn: async () => {
        console.log(`  PUT — Full Replace (Watch the Data Loss)`);
        console.log();
        console.log(`  PUT https://scim.example.com/v2/Users/${scimUser.id}`);
        console.log(`  Content-Type: application/scim+json`);
        console.log();
        console.log(`  ${JSON.stringify(putBody, null, 4).split('\n').join('\n  ')}`);
        console.log();
        console.log(`  Notice: the PUT body has name and active. But emails and groups`);
        console.log(`  are NOT in the body.`);
        console.log();
        console.log(`  BEFORE:                                     AFTER:`);
        console.log(`  ─────────────────────────────────            ─────────────────────────────────`);
        console.log(`  "userName": "${scimUser.userName}"     "userName": "${scimUser.userName}"`);
        console.log(`  "name": {                                    "name": {`);
        console.log(`    "givenName": "Jordan",                       "givenName": "Jordan",`);
        console.log(`    "familyName": "Martinez"                     "familyName": "Martinez"`);
        console.log(`  }                                            }`);
        console.log(`  "emails": [                                  "emails": []                      ← GONE`);
        console.log(`    { "value": "j.martinez@example.com",`);
        console.log(`      "type": "work", "primary": true },`);
        console.log(`    { "value": "jordan.m@personal.com",`);
        console.log(`      "type": "home" }`);
        console.log(`  ]`);
        console.log(`  "active": true                               "active": false                   ← changed`);
        console.log(`  "groups": [                                  "groups": []                      ← GONE`);
        console.log(`    { "display": "Engineering" },`);
        console.log(`    { "display": "Platform Team" }`);
        console.log(`  ]`);
        console.log();
        console.log(`  2 emails — GONE. 2 group memberships — GONE.`);
        console.log();
        console.log(`  PUT replaces the ENTIRE resource. Any field not in the PUT body is`);
        console.log(`  deleted. PUT means "this is the complete new state of this resource."`);
        console.log(`  If you omit a field, you're saying "this field should not exist."`);
        console.log();
        console.log(`  🎯 INTERVIEW ALERT: "What's the difference between PATCH and PUT in SCIM?"`);
        console.log(`     PATCH applies surgical changes — only specified fields are modified.`);
        console.log(`     PUT replaces the ENTIRE resource — any field not in the body is`);
        console.log(`     deleted. Always use PATCH for partial updates. PUT is for complete`);
        console.log(`     replacement only.`);
      },
    },
    {
      name: 'DELETE with proper cascade',
      fn: async () => {
        console.log(`  DELETE with Proper Cascade`);
        console.log();
        console.log(`  DELETE https://scim.example.com/v2/Users/${scimUser.id}`);
        console.log(`  HTTP/1.1 204 No Content`);
        console.log();
        console.log(`  But DELETE isn't just removing a database row. A proper deprovisioning`);
        console.log(`  cascade has 4 steps:`);
        console.log();
        console.log(`  ┌─────┐    ┌──────────┐    ┌──────────┐    ┌────────────┐`);
        console.log(`  │  1  │───▶│    2     │───▶│    3     │───▶│     4      │`);
        console.log(`  │ Set │    │ Revoke   │    │ Emit SET │    │ Downstream │`);
        console.log(`  │false│    │ sessions │    │ event    │    │ kills      │`);
        console.log(`  └─────┘    └──────────┘    └──────────┘    └────────────┘`);
        console.log();
        console.log(`  Step 1: Set active=false`);
        console.log(`    The user is immediately disabled. No new sessions, no new tokens.`);
        console.log();
        console.log(`  Step 2: Revoke all active sessions`);
        console.log(`    The IdP invalidates all current sessions for this user at the`);
        console.log(`    identity provider level.`);
        console.log();
        console.log(`  Step 3: Emit a CAEP session-revoked SET (Security Event Token) event`);
        console.log(`    The IdP pushes a real-time signal to downstream services:`);
        console.log();
        console.log(`  Decoded SET event payload:`);
        console.log(`  {`);
        console.log(`    "iss": "${setEventPayload.iss}",`);
        console.log(`        ↳ Issuer. The IdP that emitted this event.`);
        console.log();
        console.log(`    "iat": ${setEventPayload.iat},`);
        console.log(`        ↳ Issued At. Unix timestamp — when the event was created.`);
        console.log();
        console.log(`    "jti": "${setEventPayload.jti}",`);
        console.log(`        ↳ JWT ID. Unique identifier for this event. Receivers use`);
        console.log(`          this for deduplication — process each event exactly once.`);
        console.log();
        console.log(`    "aud": "${setEventPayload.aud}",`);
        console.log(`        ↳ Audience. The downstream service that should act on this.`);
        console.log();
        console.log(`    "events": {`);
        console.log(`      "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {`);
        console.log(`          ↳ Event type URI. Identifies this as a CAEP session-revoked`);
        console.log(`            event. The receiver knows exactly what action to take.`);
        console.log();
        console.log(`        "subject": {`);
        console.log(`          "format": "opaque",`);
        console.log(`          "id": "${sessionId}"`);
        console.log(`        },`);
        console.log(`            ↳ Subject. The session being revoked. "opaque" format means`);
        console.log(`              the ID is an opaque string (not an email or URI).`);
        console.log();
        console.log(`        "event_timestamp": ${setEventPayload.events['https://schemas.openid.net/secevent/caep/event-type/session-revoked'].event_timestamp},`);
        console.log(`            ↳ Event Timestamp. When the revocation actually happened`);
        console.log(`              (may differ from iat if there's processing delay).`);
        console.log();
        console.log(`        "reason_admin": { "en": "User deprovisioned via SCIM DELETE" }`);
        console.log(`            ↳ Admin Reason. Human-readable explanation for audit logs.`);
        console.log(`              Localized — "en" key for English.`);
        console.log(`      }`);
        console.log(`    }`);
        console.log(`  }`);
        console.log();
        console.log(`  (In Experiment 8, you'll construct and sign these as real JWTs`);
        console.log(`   with typ: secevent+jwt.)`);
        console.log();
        console.log(`  Step 4: Downstream services receive the event and kill sessions`);
        console.log(`    Within seconds, every downstream service has terminated the user's`);
        console.log(`    sessions. Access gone. No waiting for token expiry.`);
        console.log();
        console.log(`  Deprovisioning must be fast. A terminated employee's access should`);
        console.log(`  be gone in seconds, not minutes.`);
      },
    },
    {
      name: 'DELETE without CAEP (revocation gap)',
      fn: async () => {
        console.log(`  DELETE without CAEP — The Revocation Timing Gap`);
        console.log();
        console.log(`  Same DELETE, but no CAEP event. The user is disabled in the IdP,`);
        console.log(`  but existing sessions at downstream services continue working.`);
        console.log(`  Self-contained JWTs can't be revoked until they expire.`);
        console.log();
        console.log(`  Token TTL = ${tokenTTL}s (${tokenTTL / 60} minutes)`);
        console.log();
        console.log(`  ──────────────────────────────────────────────────────────────`);
        console.log(`  WITHOUT CAEP:`);
        console.log(`  ──────────────────────────────────────────────────────────────`);
        console.log();
        console.log(`  min 0     Token issued (TTL = ${tokenTTL / 60} min)`);
        console.log(`            └─ JWT is self-contained, signed, valid for 10 min`);
        console.log();
        console.log(`  min 2     DELETE /Users/${scimUser.id}`);
        console.log(`            └─ User disabled in IdP. But downstream doesn't know.`);
        console.log();
        console.log(`  min 3     API call with token → ACCEPTED ⚠️`);
        console.log(`            └─ Token signature valid, exp not reached. No revocation.`);
        console.log();
        console.log(`  min 5     API call with token → ACCEPTED ⚠️`);
        console.log(`            └─ Still valid. Downstream has no way to know user is gone.`);
        console.log();
        console.log(`  min 8     API call with token → ACCEPTED ⚠️`);
        console.log(`            └─ 6 minutes after termination. Still full access.`);
        console.log();
        console.log(`  min 10    Token expires → REJECTED ✅`);
        console.log(`            └─ Finally. 8 minutes of unauthorized access.`);
        console.log();
        console.log(`  Gap: 8 minutes of access after the user was terminated.`);
        console.log();

        await pause();

        console.log(`  ──────────────────────────────────────────────────────────────`);
        console.log(`  WITH CAEP:`);
        console.log(`  ──────────────────────────────────────────────────────────────`);
        console.log();
        console.log(`  min 0       Token issued (TTL = ${tokenTTL / 60} min)`);
        console.log();
        console.log(`  min 2       DELETE /Users/${scimUser.id}`);
        console.log(`              └─ User disabled in IdP.`);
        console.log();
        console.log(`  min 2.000   SET event emitted (session-revoked)`);
        console.log(`              └─ IdP pushes revocation signal to all downstream.`);
        console.log();
        console.log(`  min 2.001   Downstream receives SET → session killed ✅`);
        console.log(`              └─ Token still technically "valid" but session is dead.`);
        console.log();
        console.log(`  min 3       API call with token → REJECTED ✅`);
        console.log(`              └─ Session already terminated. Access denied.`);
        console.log();
        console.log(`  Gap: milliseconds.`);
        console.log();
        console.log(`  🎯 INTERVIEW ALERT: "What is the revocation timing gap?"`);
        console.log(`     Time between user deprovisioning and token expiry. Self-contained`);
        console.log(`     JWTs can't be revoked until they expire. With a ${tokenTTL / 60}-minute TTL,`);
        console.log(`     that's up to ${tokenTTL / 60} minutes of unauthorized access after termination.`);
        console.log(`     CAEP closes this gap to milliseconds by pushing real-time`);
        console.log(`     revocation signals to downstream services.`);
      },
    },
    {
      name: 'Continue (SCIM vs JIT + lifecycle)',
      fn: async () => {
        console.log(`  SCIM vs JIT Provisioning`);
        console.log();
        console.log(`  ┌──────────────────┬─────────────────────────┬──────────────────────────┐`);
        console.log(`  │                  │  SCIM (Push)            │  JIT (Just-In-Time)      │`);
        console.log(`  ├──────────────────┼─────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Provisioning    │  Pre-provisioned.       │  Created on first login  │`);
        console.log(`  │  timing          │  Account exists before  │  from OIDC token claims  │`);
        console.log(`  │                  │  user's first login.    │  (Experiment 1).         │`);
        console.log(`  ├──────────────────┼─────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Attribute       │  Full control. PATCH to │  Only on login. If email │`);
        console.log(`  │  updates         │  update any field at    │  changes in IdP, service │`);
        console.log(`  │                  │  any time.              │  won't know until next   │`);
        console.log(`  │                  │                         │  auth.                   │`);
        console.log(`  ├──────────────────┼─────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Deprovisioning  │  DELETE + cascade.      │  None. No mechanism to   │`);
        console.log(`  │                  │  Active revocation.     │  remove accounts. User   │`);
        console.log(`  │                  │                         │  just stops logging in.  │`);
        console.log(`  ├──────────────────┼─────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Complexity      │  Higher. Requires SCIM  │  Lower. Just parse OIDC  │`);
        console.log(`  │                  │  server + webhook infra │  claims on login.        │`);
        console.log(`  │                  │  + monitoring.          │                          │`);
        console.log(`  ├──────────────────┼─────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Best for        │  Enterprise. Compliance │  SaaS onboarding. Low    │`);
        console.log(`  │                  │  requires audit trail + │  friction. Acceptable    │`);
        console.log(`  │                  │  active deprovisioning. │  when deprov isn't       │`);
        console.log(`  │                  │                         │  critical.               │`);
        console.log(`  └──────────────────┴─────────────────────────┴──────────────────────────┘`);
        console.log();
        console.log(`  🎯 INTERVIEW ALERT: "SCIM vs JIT provisioning — when would you use each?"`);
        console.log(`     SCIM = push provisioning, full lifecycle (create/update/delete).`);
        console.log(`     JIT = account created on first login from OIDC claims (Experiment 1).`);
        console.log(`     JIT is simpler but has no deprovisioning mechanism. Use SCIM when`);
        console.log(`     compliance requires active deprovisioning and audit trails.`);
        console.log();

        await pause();

        console.log(`  Full Identity Lifecycle`);
        console.log();
        console.log(`  Every identity moves through these stages — each one maps to an`);
        console.log(`  experiment in this series:`);
        console.log();
        console.log(`  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐`);
        console.log(`  │  1. Identity  │───▶│  2. WebAuthn │───▶│ 3. Provision │`);
        console.log(`  │   Proofing   │    │ Registration │    │  (SCIM/JIT)  │`);
        console.log(`  └──────────────┘    └──────────────┘    └──────────────┘`);
        console.log(`         │                    │                    │`);
        console.log(`    IAL1: self-asserted  Experiment 3        This experiment`);
        console.log(`    IAL2: remote ID +    (passkey/cred       (SCIM) or`);
        console.log(`          photo + selfie  creation)          Experiment 1 (JIT)`);
        console.log(`    IAL3: in-person                                │`);
        console.log(`         verification                              ▼`);
        console.log(`                                          ┌──────────────┐`);
        console.log(`  ┌──────────────┐    ┌──────────────┐    │ 4. Authn     │`);
        console.log(`  │ 7. Deprov    │◀───│ 6. API       │◀───│  (Login)     │`);
        console.log(`  │ SCIM DELETE  │    │  Access      │    │              │`);
        console.log(`  │ + CAEP       │    │  (DPoP)      │    └──────────────┘`);
        console.log(`  │ (Exp 8)      │    │  (Exp 2)     │           │`);
        console.log(`  └──────────────┘    └──────────────┘           ▼`);
        console.log(`                                          ┌──────────────┐`);
        console.log(`                                          │ 5. Session   │`);
        console.log(`                                          │  Binding     │`);
        console.log(`                                          │  (DBSC)      │`);
        console.log(`                                          │  (Exp 2)     │`);
        console.log(`                                          └──────────────┘`);
        console.log();
        console.log(`  1. IAL verification (NIST 800-63)`);
        console.log(`  2. WebAuthn registration (Experiment 3)`);
        console.log(`  3. Provisioning — SCIM (this experiment) or JIT (Experiment 1)`);
        console.log(`  4. Authentication`);
        console.log(`  5. Session binding with DBSC (Experiment 2)`);
        console.log(`  6. API access with DPoP (Experiment 2)`);
        console.log(`  7. Deprovisioning — SCIM DELETE + CAEP (Experiment 8)`);
      },
    },
  ]);

  console.log();
  await pause();

  // ── Summary Card ────────────────────────────────────────────

  console.log(`╔══════════════════════════════════════════════════════════════════╗
║  SUMMARY CARD                                                    ║
║  Cover the answers below. Try to answer each from memory.        ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Q: What is SCIM?                                                ║
║  A: REST API (RFC 7644) for provisioning/deprovisioning users.   ║
║     IdP pushes lifecycle events (create/update/delete) to        ║
║     services.                                                    ║
║                                                                  ║
║  Q: PATCH vs PUT?                                                ║
║  A: PATCH modifies specified fields only. PUT replaces the       ║
║     entire resource — missing fields are deleted.                ║
║                                                                  ║
║  Q: What is the revocation timing gap?                           ║
║  A: Time between deprovisioning and token expiry. 10-min TTL     ║
║     = up to 10 min unauthorized access. CAEP closes it to        ║
║     milliseconds.                                                ║
║                                                                  ║
║  Q: SCIM vs JIT provisioning?                                    ║
║  A: SCIM = push, full lifecycle. JIT = lazy on first login,      ║
║     no deprovisioning.                                           ║
║                                                                  ║
║  Q: Full identity lifecycle?                                     ║
║  A: IAL verification → WebAuthn registration → provisioning →    ║
║     authentication → session binding (DBSC) → API access (DPoP)  ║
║     → deprovisioning (SCIM DELETE + CAEP).                       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`);

  // ── Practice Prompt ─────────────────────────────────────────

  console.log(`  ⏸  PRACTICE: Close this terminal. Explain out loud the difference`);
  console.log(`     between PATCH and PUT in SCIM, what happens when you DELETE a`);
  console.log(`     user without CAEP (the revocation timing gap), and how the full`);
  console.log(`     identity lifecycle connects from identity proofing through`);
  console.log(`     deprovisioning. Then come back and check.`);
  console.log();

  close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
