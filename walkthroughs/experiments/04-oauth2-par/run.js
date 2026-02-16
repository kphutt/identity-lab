#!/usr/bin/env node

// Experiment 4: OAuth2 Grants + PAR (FAPI 2.0)
// Layer: Identity/Grant
// Run: node run.js (interactive) or node run.js --no-pause (full dump)

import { createHash, randomBytes } from 'node:crypto';
import { createCLI, ensureDeps } from '../../shared/cli.js';

const NO_PAUSE = process.argv.includes('--no-pause');
const { pause, explore, close } = createCLI({ noPause: NO_PAUSE });

// ── Main ────────────────────────────────────────────────────────

async function main() {
  await ensureDeps(import.meta.url);
  const jose = await import('jose');

  // ── Key Generation ──────────────────────────────────────────
  // AS signing keypair — signs access tokens (at+jwt) and ID tokens
  const { publicKey: asPublicKey, privateKey: asPrivateKey } =
    await jose.generateKeyPair('ES256');
  const asPublicJwk = await jose.exportJWK(asPublicKey);
  const asKid = `as-key-${new Date().toISOString().slice(0, 10)}`;
  asPublicJwk.kid = asKid;
  asPublicJwk.use = 'sig';
  asPublicJwk.alg = 'ES256';

  // Client keypair — used for private_key_jwt client authentication
  const { publicKey: clientPublicKey, privateKey: clientPrivateKey } =
    await jose.generateKeyPair('ES256');
  const clientPublicJwk = await jose.exportJWK(clientPublicKey);
  const clientJkt = await jose.calculateJwkThumbprint(clientPublicJwk, 'sha256');

  // ── Pre-built Artifacts ─────────────────────────────────────
  const now = Math.floor(Date.now() / 1000);

  // PKCE values — real SHA-256 computation
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

  // Protocol random values
  const state = randomBytes(16).toString('base64url');
  const nonce = randomBytes(16).toString('base64url');

  // Mock authorization code
  const authorizationCode = `code-${randomBytes(16).toString('hex')}`;

  // PAR request_uri (opaque reference per RFC 9126)
  const requestUri = `urn:ietf:params:oauth:request_uri:${randomBytes(16).toString('hex')}`;

  // Signed access token (at+jwt)
  const accessToken = await new jose.SignJWT({
    iss: 'https://as.example.com',
    sub: 'user-8492',
    aud: 'https://api.example.com',
    client_id: 'client-app-xyz',
    scope: 'openid profile email',
    exp: now + 3600,
    iat: now,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: asKid })
    .sign(asPrivateKey);

  // Signed ID token
  const idToken = await new jose.SignJWT({
    iss: 'https://as.example.com',
    sub: 'user-8492',
    aud: 'client-app-xyz',
    nonce,
    auth_time: now - 30,
    exp: now + 3600,
    iat: now,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: asKid })
    .sign(asPrivateKey);

  // Opaque refresh token
  const refreshToken = `rt-${randomBytes(32).toString('hex')}`;

  // Client assertion for private_key_jwt
  const clientAssertion = await new jose.SignJWT({
    iss: 'client-app-xyz',
    sub: 'client-app-xyz',
    aud: 'https://as.example.com/oauth/token',
    exp: now + 60,
    iat: now,
    jti: randomBytes(16).toString('hex'),
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
    .sign(clientPrivateKey);

  // ── Title Card ──────────────────────────────────────────────

  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  Experiment 4: OAuth2 Grants + PAR (FAPI 2.0)                  ║
║  Layer: Identity/Grant                                          ║
║  Time: ~25 minutes                                              ║
║                                                                  ║
║  Step through with ENTER. Use --no-pause for full dump.          ║
╚══════════════════════════════════════════════════════════════════╝

  OAuth2 is the authorization framework that lets users grant apps
  limited access to their resources without sharing passwords. The
  Authorization Code flow is its cornerstone — but on its own, it has
  gaps. PKCE closes the code interception gap. PAR closes the parameter
  tampering gap. Together with sender-constrained tokens (Experiment 2),
  they form the FAPI 2.0 security profile.
`);
  await pause();

  // ── STEP 1: Authorization Code Flow — Overview ────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 1: Authorization Code Flow — Overview

  The flow has three steps:

  1. Authorization Request — Client redirects the user's browser to
     the Authorization Server (AS) with parameters describing what
     access is needed.

  2. Authorization Response — After the user authenticates and consents,
     the AS redirects back to the client with a short-lived authorization
     code in the URL.

  3. Token Exchange — The client sends the code directly to the AS
     (server-to-server, NOT through the browser) and gets back tokens.

  ┌──────────┐         ┌─────────┐         ┌──────────────────────┐
  │  User /  │         │  Client │         │  Authorization       │
  │  Browser │         │  (App)  │         │  Server (AS)         │
  └────┬─────┘         └────┬────┘         └──────────┬───────────┘
       │  1. Click "Login"  │                         │
       │───────────────────>│                         │
       │                    │  2. Redirect to AS      │
       │<───────────────────│    /authorize?params     │
       │                    │                         │
       │  3. User authenticates + consents            │
       │─────────────────────────────────────────────>│
       │                    │                         │
       │  4. Redirect back with ?code=...             │
       │<─────────────────────────────────────────────│
       │                    │                         │
       │  5. Code to client │                         │
       │───────────────────>│                         │
       │                    │  6. Exchange code for   │
       │                    │     tokens (back channel)│
       │                    │────────────────────────>│
       │                    │                         │
       │                    │  7. Tokens returned     │
       │                    │<────────────────────────│
       └                    └                         └

  🎯 INTERVIEW ALERT: "Why is the token exchange done server-to-server?"
     The authorization code is exchanged over a direct server-to-server
     connection (back channel), not through the browser. This prevents
     the tokens from being exposed in browser history, logs, or to
     JavaScript. The code itself is short-lived and single-use.
`);
  await pause();

  // ── STEP 2: The Authorization Request ─────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 2: The Authorization Request

  The client redirects the user's browser to this URL:

  GET https://as.example.com/authorize?
    response_type=code
        ↳ Response Type. "code" means the AS should return an
          authorization code (not a token directly). This is the
          Authorization Code flow.

    &client_id=client-app-xyz
        ↳ Client ID. Identifies which application is making the
          request. Pre-registered with the AS.

    &redirect_uri=https://app.example.com/callback
        ↳ Redirect URI. Where the AS sends the user back after
          authentication. MUST be pre-registered and exactly matched
          to prevent open redirector attacks.

    &scope=openid profile email
        ↳ Scope. What access the client is requesting. "openid"
          triggers OIDC (ID token). "profile" and "email" request
          user info claims.

    &state=${state}
        ↳ State. Random value generated by the client. The AS echoes
          it back on the redirect. Client checks it matches to prevent
          CSRF attacks on the redirect endpoint.

    &nonce=${nonce}
        ↳ Nonce. Random value bound to the ID token. The AS includes
          it in the ID token claims. Client checks it matches to prevent
          token replay attacks.

    &code_challenge=${codeChallenge}
        ↳ Code Challenge. SHA-256 hash of the code_verifier (PKCE).
          The AS stores this. Details in Step 3.

    &code_challenge_method=S256
        ↳ Code Challenge Method. "S256" = SHA-256. The AS knows how
          to verify the challenge later. Never use "plain" — it sends
          the verifier in the clear.

  🎯 INTERVIEW ALERT: "What's the difference between state and nonce?"
     state = CSRF protection on the redirect (client generates, checks
     on callback). nonce = replay protection for the ID token (echoed
     in the token, client checks). They protect different things at
     different steps.
`);
  await pause();

  // ── STEP 3: PKCE ──────────────────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 3: PKCE (Proof Key for Code Exchange, "pixie", RFC 7636)

  PKCE binds the authorization code to the client that started the
  flow. Without it, anyone who intercepts the code can exchange it
  for tokens. Here's the full mechanism with real values:

  1. Generate code_verifier (43-128 chars, cryptographically random):
     code_verifier = "${codeVerifier}"
     (${codeVerifier.length} characters, base64url-encoded random bytes)

  2. Compute code_challenge = base64url(SHA-256(code_verifier)):
     SHA-256("${codeVerifier}")
     = "${codeChallenge}"
     This is a HASH of the secret — not the secret itself.

  3. Send code_challenge + method in the authorization request:
     code_challenge=${codeChallenge}
     code_challenge_method=S256
     The AS stores this hash alongside the authorization code.

  4. AS authenticates the user, issues the authorization code, and
     stores the code_challenge associated with it.

  5. Client sends the original code_verifier in the token request:
     code_verifier=${codeVerifier}
     This goes server-to-server (back channel) — never in the browser.

  6. AS re-computes: base64url(SHA-256(received_verifier))
     and compares to the stored code_challenge.

  7. Match → tokens issued. No match → REJECTED.

  Security: An attacker who intercepts the authorization code only
  sees the code_challenge (the hash). SHA-256 is one-way — knowing
  the hash doesn't reveal the verifier. Without the verifier, the
  attacker can't complete step 5.

  🎯 S256 vs plain: "plain" sends the verifier as the challenge
     (no hashing). An attacker who sees the challenge can use it
     directly. Always use S256. Mandatory in OAuth 2.1.
`);
  await pause();

  // ── STEP 4: Token Request ─────────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 4: Token Request

  The client sends the authorization code to the token endpoint
  server-to-server (back channel):

  POST https://as.example.com/oauth/token
  Content-Type: application/x-www-form-urlencoded
  (Shown as annotated JSON for readability — the actual wire format
  is key=value&key=value)

  {
    "grant_type": "authorization_code",
        ↳ Grant Type. Identifies this as an authorization code
          exchange. The AS knows to expect a code + code_verifier.

    "code": "${authorizationCode}",
        ↳ Authorization Code. The short-lived, single-use code from
          the redirect. The RFC recommends a max lifetime of 10
          minutes (RFC 6749 §4.1.2), and most implementations use
          30 seconds to a few minutes.

    "redirect_uri": "https://app.example.com/callback",
        ↳ Redirect URI. Must EXACTLY match the one in the
          authorization request. The AS compares both to prevent
          redirect manipulation attacks.

    "client_id": "client-app-xyz",
        ↳ Client ID. Identifies the client. For public clients
          (SPAs, mobile apps), this is the only client identifier.
          Confidential clients also send client authentication.

    "code_verifier": "${codeVerifier}"
        ↳ Code Verifier. The original PKCE secret. The AS hashes
          this with SHA-256 and compares to the stored code_challenge.
          This is what proves YOU started the flow.
  }
`);
  await pause();

  // ── STEP 5: Token Response ────────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 5: Token Response

  The AS validates the code, verifies PKCE, and returns tokens:

  HTTP/1.1 200 OK
  Content-Type: application/json
  Cache-Control: no-store

  {
    "access_token": "${accessToken.slice(0, 40)}...",
        ↳ Access Token. A signed JWT (typ: at+jwt, from Experiment 1)
          for calling protected APIs. Contains sub, aud, scope, exp.
          Resource servers validate this on every API call.

    "token_type": "Bearer",
        ↳ Token Type. "Bearer" means possession = access. For
          sender-constrained tokens, this would be "DPoP"
          (from Experiment 2) — requiring proof of key possession.

    "expires_in": 3600,
        ↳ Expires In. Seconds until the access token expires.
          Short-lived (minutes to hours) to limit blast radius
          of token theft. Use refresh tokens for longer sessions.

    "id_token": "${idToken.slice(0, 40)}...",
        ↳ ID Token. OIDC identity assertion (from Experiment 1).
          Contains sub (who the user is), nonce (replay protection),
          auth_time (when they logged in). Audience is the client,
          not the resource server.

    "refresh_token": "${refreshToken.slice(0, 30)}..."
        ↳ Refresh Token. Opaque string (not a JWT). Used to get
          new access tokens without re-authenticating the user.
          Stored securely by the client, never sent to resource
          servers. Best practice (required by OAuth 2.1): each use
          returns a new refresh token and invalidates the old one
          (rotation). RFC 6749 §6 says the AS "MAY issue a new
          refresh token" — not all implementations rotate.
  }
`);
  await pause();

  // ── STEP 6: Client Credentials Grant ──────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 6: Client Credentials Grant

  Machine-to-machine flow — no user involved. The client IS the
  resource owner. Used for service-to-service communication,
  background jobs, infrastructure automation.

  POST https://as.example.com/oauth/token
  Content-Type: application/x-www-form-urlencoded
  (Shown as annotated JSON for readability — the actual wire format
  is key=value&key=value)

  {
    "grant_type": "client_credentials",
        ↳ Grant Type. No authorization code, no user interaction.
          The client authenticates itself directly to get a token.

    "client_id": "client-app-xyz",
        ↳ Client ID. Identifies the client application.

    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ↳ Client Assertion Type. Indicates the client is using
          private_key_jwt for authentication (instead of a shared
          client_secret). The client signs a JWT with its private key.

    "client_assertion": "${clientAssertion.slice(0, 40)}...",
        ↳ Client Assertion. A JWT signed by the client's private key.
          Contains iss=client_id, aud=token_endpoint, exp, jti.
          The AS verifies using the client's registered public key.
          More secure than client_secret — no shared secret to leak.

    "scope": "read:metrics write:logs"
        ↳ Scope. Permissions for machine-to-machine access.
          No "openid" — there's no user identity to assert.
  }

  Response:

  {
    "access_token": "<signed at+jwt>",
    "token_type": "Bearer",
    "expires_in": 3600
  }

  Notice: No id_token (no user), no refresh_token (the client can
  re-authenticate anytime with its credentials — no need to store
  a refresh token).
`);
  await pause();

  // ── STEP 7: Authorization Flow Lab (Exploration Point) ────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 7: Authorization Flow Lab

  Let's compare baseline OAuth2 with PAR and see how PKCE stops
  the authorization code interception attack.`);

  await explore('Pick a scenario to explore:', [
    {
      name: 'Baseline OAuth2 (params in URL)',
      fn: async () => {
        console.log(`  In baseline OAuth2, ALL parameters go in the browser URL bar:`);
        console.log();
        console.log(`  https://as.example.com/authorize?`);
        console.log(`    response_type=code`);
        console.log(`    &client_id=client-app-xyz`);
        console.log(`    &redirect_uri=https://app.example.com/callback`);
        console.log(`    &scope=openid profile email`);
        console.log(`    &state=${state}`);
        console.log(`    &code_challenge=${codeChallenge}`);
        console.log(`    &code_challenge_method=S256`);
        console.log(`    &login_hint=alice@corp.example.com`);
        console.log();
        console.log(`  Problems with parameters in the URL:`);
        console.log();
        console.log(`  1. PII visible — login_hint exposes the user's email in the`);
        console.log(`     address bar, browser history, proxy logs, and referrer headers.`);
        console.log();
        console.log(`  2. Tamperable — an attacker (or browser extension) can modify`);
        console.log(`     redirect_uri, scope, or other params before the request`);
        console.log(`     reaches the AS. The AS may not detect the change.`);
        console.log();
        console.log(`  3. URL length limits — some browsers and proxies truncate`);
        console.log(`     URLs over ~2000 characters. Complex requests with many`);
        console.log(`     scopes or claims can exceed this.`);
        console.log();
        console.log(`  4. No client authentication — the authorization request`);
        console.log(`     comes through the browser, so the AS can't verify the`);
        console.log(`     client's identity at this stage.`);
      },
    },
    {
      name: 'PAR (server-to-server push)',
      fn: async () => {
        console.log(`  PAR (Pushed Authorization Requests, RFC 9126)`);
        console.log();
        console.log(`  Instead of putting params in the URL, the client POSTs them`);
        console.log(`  directly to the AS server-to-server:`);
        console.log();
        console.log(`  POST https://as.example.com/as/par`);
        console.log(`  Content-Type: application/x-www-form-urlencoded`);
        console.log(`  (Shown as annotated JSON for readability — the actual wire format`);
        console.log(`  is key=value&key=value)`);
        console.log();
        console.log(`  {`);
        console.log(`    "response_type": "code",`);
        console.log(`    "client_id": "client-app-xyz",`);
        console.log(`    "redirect_uri": "https://app.example.com/callback",`);
        console.log(`    "scope": "openid profile email",`);
        console.log(`    "state": "${state}",`);
        console.log(`    "nonce": "${nonce}",`);
        console.log(`    "code_challenge": "${codeChallenge}",`);
        console.log(`    "code_challenge_method": "S256",`);
        console.log(`    "login_hint": "alice@corp.example.com",`);
        console.log();
        console.log(`    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",`);
        console.log(`    "client_assertion": "${clientAssertion.slice(0, 40)}..."`);
        console.log(`        ↳ Client authentication via private_key_jwt. The AS`);
        console.log(`          verifies the client's identity BEFORE processing`);
        console.log(`          the authorization request.`);
        console.log(`  }`);
        console.log();
        console.log(`  Response:`);
        console.log(`  HTTP/1.1 201 Created`);
        console.log(`  {`);
        console.log(`    "request_uri": "${requestUri}",`);
        console.log(`        ↳ An opaque reference to the stored parameters.`);
        console.log(`          The AS generated this and remembers what it maps to.`);
        console.log();
        console.log(`    "expires_in": 60`);
        console.log(`        ↳ The request_uri is valid for 60 seconds. The client`);
        console.log(`          must redirect the user to the AS before it expires.`);
        console.log(`  }`);
        console.log();
        console.log(`  Now the authorization URL is just:`);
        console.log();
        console.log(`  https://as.example.com/authorize?`);
        console.log(`    client_id=client-app-xyz`);
        console.log(`    &request_uri=${requestUri}`);
        console.log();
        console.log(`  That's it. No PII. No tamperable params. The AS looks up the`);
        console.log(`  request_uri to find the real parameters, which were delivered`);
        console.log(`  server-to-server and authenticated.`);
        console.log();
        console.log(`  🎯 INTERVIEW ALERT: "What is PAR and why does FAPI 2.0 require it?"`);
        console.log(`     PAR (RFC 9126) lets the client POST params to the AS`);
        console.log(`     server-to-server. AS returns opaque request_uri. Browser`);
        console.log(`     sees only client_id + request_uri. Prevents parameter`);
        console.log(`     tampering, hides PII, and authenticates the client early.`);
      },
    },
    {
      name: 'No PKCE — code interception attack',
      fn: async () => {
        console.log(`  Authorization Code Interception Attack (without PKCE)`);
        console.log();
        console.log(`  Setup: A malicious app is installed on the user's device and`);
        console.log(`  has registered the same custom URL scheme (e.g., myapp://) as`);
        console.log(`  the legitimate app.`);
        console.log();
        console.log(`  Step 1: Legitimate app starts OAuth2 flow`);
        console.log(`    → Redirects to AS: /authorize?response_type=code&client_id=...`);
        console.log(`    → No code_challenge (PKCE not used)`);
        console.log();
        console.log(`  Step 2: User authenticates and consents at the AS`);
        console.log();
        console.log(`  Step 3: AS redirects back with authorization code`);
        console.log(`    → myapp://callback?code=${authorizationCode.slice(0, 20)}...`);
        console.log();
        console.log(`  Step 4: BOTH apps receive the redirect (same URL scheme)`);
        console.log(`    → Legitimate app: has the code`);
        console.log(`    → Malicious app:  ALSO has the code ⚠️`);
        console.log();
        console.log(`  Step 5: Malicious app races to the token endpoint first`);
        console.log(`    POST /oauth/token`);
        console.log(`    {`);
        console.log(`      "grant_type": "authorization_code",`);
        console.log(`      "code": "${authorizationCode.slice(0, 20)}...",`);
        console.log(`      "client_id": "client-app-xyz",`);
        console.log(`      "redirect_uri": "myapp://callback"`);
        console.log(`    }`);
        console.log();
        console.log(`  Step 6: AS checks — valid code, valid client_id, valid redirect_uri`);
        console.log(`    → No proof that this client started the flow`);
        console.log(`    → Result: ACCEPTED ⚠️  Tokens issued to attacker!`);
        console.log();
        console.log(`  Root cause: Without PKCE, the AS has no way to verify that the`);
        console.log(`  client exchanging the code is the same client that requested it.`);
        console.log(`  The code is a bearer credential — possession is enough.`);
      },
    },
    {
      name: 'With PKCE — attack defeated',
      fn: async () => {
        // Re-compute to demonstrate the match
        const recomputed = createHash('sha256').update(codeVerifier).digest('base64url');

        console.log(`  Same Attack Scenario — But With PKCE`);
        console.log();
        console.log(`  Setup: Same malicious app, same URL scheme interception.`);
        console.log();
        console.log(`  Step 1: Legitimate app starts OAuth2 flow with PKCE`);
        console.log(`    → Generates code_verifier: "${codeVerifier.slice(0, 20)}..."`);
        console.log(`    → Computes code_challenge:  "${codeChallenge.slice(0, 20)}..."`);
        console.log(`    → Sends code_challenge in /authorize request`);
        console.log(`    → Keeps code_verifier secret (never sent to browser)`);
        console.log();
        console.log(`  Step 2: User authenticates. AS stores code_challenge.`);
        console.log();
        console.log(`  Step 3: AS redirects back with code (same as before)`);
        console.log(`    → myapp://callback?code=${authorizationCode.slice(0, 20)}...`);
        console.log();
        console.log(`  Step 4: Malicious app intercepts the code (same as before)`);
        console.log();
        console.log(`  Step 5: Malicious app tries to exchange the code`);
        console.log(`    POST /oauth/token`);
        console.log(`    {`);
        console.log(`      "grant_type": "authorization_code",`);
        console.log(`      "code": "${authorizationCode.slice(0, 20)}...",`);
        console.log(`      "client_id": "client-app-xyz",`);
        console.log(`      "redirect_uri": "myapp://callback"`);
        console.log(`      — NO code_verifier (attacker doesn't have it)`);
        console.log(`    }`);
        console.log();
        console.log(`  Step 6: AS checks — code_verifier missing or wrong`);
        console.log(`    → Result: REJECTED ✅  No verifier = no tokens.`);
        console.log();

        await pause();

        console.log(`  Step 7: Legitimate app exchanges the code WITH the verifier`);
        console.log(`    POST /oauth/token`);
        console.log(`    {`);
        console.log(`      "grant_type": "authorization_code",`);
        console.log(`      "code": "${authorizationCode.slice(0, 20)}...",`);
        console.log(`      "client_id": "client-app-xyz",`);
        console.log(`      "redirect_uri": "myapp://callback",`);
        console.log(`      "code_verifier": "${codeVerifier.slice(0, 20)}..."`);
        console.log(`    }`);
        console.log();
        console.log(`  Step 8: AS re-computes SHA-256(code_verifier):`);
        console.log(`    SHA-256("${codeVerifier.slice(0, 20)}...")`);
        console.log(`    = "${recomputed}"`);
        console.log();
        console.log(`    Stored code_challenge:`);
        console.log(`    = "${codeChallenge}"`);
        console.log();
        console.log(`    Match: ${recomputed === codeChallenge ? 'YES ✅' : 'NO ✗'}`);
        console.log(`    → Result: ACCEPTED ✅  Tokens issued to legitimate client.`);
        console.log();
        console.log(`  🎯 INTERVIEW ALERT: "How does PKCE prevent the authorization`);
        console.log(`     code interception attack?"`);
        console.log(`     Client sends SHA-256 hash (code_challenge) in auth request.`);
        console.log(`     Verifier sent server-to-server in token exchange. Attacker`);
        console.log(`     intercepts code but can't produce verifier. SHA-256 is`);
        console.log(`     one-way — knowing the hash doesn't give you the input.`);
      },
    },
    {
      name: 'Continue (FAPI 2.0 summary)',
      fn: async () => {
        console.log(`  FAPI 2.0 — Financial-grade API Security Profile`);
        console.log();
        console.log(`  FAPI 2.0 combines the protections from this experiment and`);
        console.log(`  Experiment 2 into a mandatory security baseline. Originally`);
        console.log(`  designed for banking, now adopted across healthcare, government,`);
        console.log(`  and any high-security API.`);
        console.log();
        console.log(`  ┌──────────────────────────┬───────────────────────────────────┐`);
        console.log(`  │  Requirement             │  Threat it addresses              │`);
        console.log(`  ├──────────────────────────┼───────────────────────────────────┤`);
        console.log(`  │  PKCE (required)         │  Authorization code interception  │`);
        console.log(`  │    ↳ code_challenge +    │  Attacker grabs code but can't    │`);
        console.log(`  │      code_verifier       │  produce the verifier (SHA-256)   │`);
        console.log(`  ├──────────────────────────┼───────────────────────────────────┤`);
        console.log(`  │  PAR (required)          │  Parameter tampering + PII leak   │`);
        console.log(`  │    ↳ RFC 9126, server-   │  Params sent server-to-server,    │`);
        console.log(`  │      to-server push      │  authenticated, not in URL bar    │`);
        console.log(`  ├──────────────────────────┼───────────────────────────────────┤`);
        console.log(`  │  Sender-constrained      │  Token theft + replay             │`);
        console.log(`  │  tokens (required)       │  DPoP (from Experiment 2) or      │`);
        console.log(`  │    ↳ DPoP or mTLS        │  mTLS binds token to client key.  │`);
        console.log(`  │    ↳ cnf.jkt             │  Stolen token useless without key │`);
        console.log(`  ├──────────────────────────┼───────────────────────────────────┤`);
        console.log(`  │  Strict redirect_uri     │  Open redirect attacks            │`);
        console.log(`  │  matching (required)     │  Exact string match, no wildcards.│`);
        console.log(`  │                          │  Prevents code delivery to        │`);
        console.log(`  │                          │  attacker-controlled endpoints    │`);
        console.log(`  ├──────────────────────────┼───────────────────────────────────┤`);
        console.log(`  │  No implicit flow        │  Token leakage via URL fragments  │`);
        console.log(`  │  (prohibited)            │  Tokens in URL fragments appear   │`);
        console.log(`  │                          │  in history, logs, referrer. Code │`);
        console.log(`  │                          │  flow + back channel exchange is  │`);
        console.log(`  │                          │  the only allowed pattern.        │`);
        console.log(`  ├──────────────────────────┼───────────────────────────────────┤`);
        console.log(`  │  JARM (optional)         │  Authorization response tampering │`);
        console.log(`  │    ↳ JWT Secured         │  AS signs the authorization       │`);
        console.log(`  │      Authorization       │  response as a JWT. Client can    │`);
        console.log(`  │      Response Mode       │  verify the response came from    │`);
        console.log(`  │                          │  the real AS, not an attacker.    │`);
        console.log(`  └──────────────────────────┴───────────────────────────────────┘`);
        console.log();
        console.log(`  FAPI 2.0 = PKCE + PAR + sender-constrained tokens + strict`);
        console.log(`  redirect URI. No single measure is enough — each closes a`);
        console.log(`  different attack surface.`);
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
║  Q: How does PKCE prevent auth code interception?                ║
║  A: Client sends hash; only original client has the verifier.    ║
║     SHA-256 is one-way — can't reverse hash to get verifier.     ║
║                                                                  ║
║  Q: What is PAR and why is it needed?                            ║
║  A: Client POSTs params server-to-server, gets opaque            ║
║     request_uri. Hides PII, prevents tampering.                  ║
║                                                                  ║
║  Q: State vs nonce?                                              ║
║  A: State = CSRF on redirect. Nonce = replay protection for      ║
║     ID token. Different artifacts, different steps.              ║
║                                                                  ║
║  Q: Client Credentials vs Auth Code?                             ║
║  A: Client Credentials = machine-to-machine (no user).           ║
║     Auth Code = user-facing (delegated access).                  ║
║                                                                  ║
║  Q: FAPI 2.0 mandatory requirements?                             ║
║  A: PKCE + PAR + sender-constrained tokens (DPoP/mTLS) +        ║
║     strict redirect_uri + no implicit flow.                      ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`);

  // ── Practice Prompt ─────────────────────────────────────────

  console.log(`  ⏸  PRACTICE: Draw the Authorization Code + PKCE flow on paper:`);
  console.log(`     authorization request (with code_challenge), redirect (with`);
  console.log(`     code), token exchange (with code_verifier). Then explain how`);
  console.log(`     PKCE prevents the interception attack and what FAPI 2.0`);
  console.log(`     requires.`);
  console.log();

  close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
