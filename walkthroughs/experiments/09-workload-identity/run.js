#!/usr/bin/env node

// Experiment 9: Workload Identity Federation
// Layer: Cross-cutting
// Run: node run.js (interactive) or node run.js --no-pause (full dump)

import { randomBytes } from 'node:crypto';
import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  jwtVerify,
  createLocalJWKSet,
  decodeProtectedHeader,
} from 'jose';
import { createCLI } from '../../shared/cli.js';

const NO_PAUSE = process.argv.includes('--no-pause');
const { pause, explore, close } = createCLI({ noPause: NO_PAUSE });

// ── Main ────────────────────────────────────────────────────────

async function main() {
  // ── Pre-built Artifacts ─────────────────────────────────────

  // K8s cluster IdP keypair (signs workload OIDC tokens)
  const { publicKey: clusterPublicKey, privateKey: clusterPrivateKey } =
    await generateKeyPair('ES256');
  const clusterPublicJwk = await exportJWK(clusterPublicKey);
  const clusterKid = 'cluster-key-' + randomBytes(4).toString('hex');
  clusterPublicJwk.kid = clusterKid;
  clusterPublicJwk.use = 'sig';
  clusterPublicJwk.alg = 'ES256';

  // Cluster's published OIDC JWKS
  const clusterJwks = { keys: [clusterPublicJwk] };

  // Cloud STS keypair (signs short-lived cloud access tokens)
  const { publicKey: stsPublicKey, privateKey: stsPrivateKey } =
    await generateKeyPair('ES256');
  const stsPublicJwk = await exportJWK(stsPublicKey);
  const stsKid = 'sts-key-' + randomBytes(4).toString('hex');
  stsPublicJwk.kid = stsKid;
  stsPublicJwk.use = 'sig';
  stsPublicJwk.alg = 'ES256';

  // Workload identifiers
  const podName = 'payment-api-' + randomBytes(3).toString('hex');
  const namespace = 'payments';
  const serviceAccount = 'payment-api';

  // Timestamps
  const now = Math.floor(Date.now() / 1000);

  // Issuers and audiences
  const clusterIssuer =
    'https://container.googleapis.com/v1/projects/my-project/locations/us-central1/clusters/prod';
  const stsUrl = 'https://sts.googleapis.com';
  const targetApi = 'https://storage.googleapis.com';

  // ── Workload OIDC Token (K8s ServiceAccount projected token) ──

  const workloadPayload = {
    iss: clusterIssuer,
    sub: `system:serviceaccount:${namespace}:${serviceAccount}`,
    aud: stsUrl,
    exp: now + 900, // 15 minutes
    iat: now,
    nbf: now,
    'kubernetes.io': {
      namespace,
      serviceaccount: {
        name: serviceAccount,
        uid: randomBytes(8).toString('hex'),
      },
      pod: {
        name: podName,
        uid: randomBytes(8).toString('hex'),
      },
    },
  };

  const workloadToken = await new SignJWT(workloadPayload)
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: clusterKid })
    .sign(clusterPrivateKey);

  // ── Cloud Access Token (issued by STS after exchange) ─────

  const federatedIdentity = `principal://iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/k8s-pool/subject/system:serviceaccount:${namespace}:${serviceAccount}`;

  const cloudAccessPayload = {
    iss: stsUrl,
    sub: federatedIdentity,
    aud: targetApi,
    exp: now + 300, // 5 minutes
    iat: now,
    scope: 'https://www.googleapis.com/auth/cloud-platform',
    token_type: 'urn:ietf:params:oauth:token-type:access_token',
  };

  const cloudAccessToken = await new SignJWT(cloudAccessPayload)
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: stsKid })
    .sign(stsPrivateKey);

  // ── SPIFFE SVID JWT ───────────────────────────────────────

  const spiffeTrustDomain = 'example.org';
  const spiffeId = `spiffe://${spiffeTrustDomain}/ns/${namespace}/sa/${serviceAccount}`;
  const targetSpiffeId = `spiffe://${spiffeTrustDomain}/ns/orders/sa/order-api`;

  const spiffeSvidPayload = {
    iss: spiffeTrustDomain,
    sub: spiffeId,
    aud: targetSpiffeId,
    exp: now + 300,
    iat: now,
  };

  const spiffeSvid = await new SignJWT(spiffeSvidPayload)
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: clusterKid })
    .sign(clusterPrivateKey);

  // ── Title Card ──────────────────────────────────────────────

  console.log(`
${'═'.repeat(66)}
  Experiment 9: Workload Identity Federation
  Layer: Cross-cutting
  Time: ~25 minutes

  Step through with ENTER. Use --no-pause for full dump.
${'═'.repeat(66)}

  WIF eliminates static secrets. Workloads authenticate with
  platform-native OIDC tokens — the same JWT format from Experiment 1,
  verified against JWKS from Experiment 6.

  The token exchange pattern (RFC 8693) lets a workload swap its
  platform-issued OIDC token for a short-lived cloud access token.
  No static secrets, no Secret Zero problem.

  Builds on: Experiment 1 (JWT format, claims)
             Experiment 6 (JWKS/kid verification)
  Capstone:  Ties all 9 experiments together.
`);
  await pause();

  // ── STEP 1: Workload Identity Token ─────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const workloadHeader = decodeProtectedHeader(workloadToken);

  console.log(`
  STEP 1: Workload Identity Token — K8s Projected ServiceAccount Token

  In Kubernetes, every pod can get an OIDC token automatically. The
  kubelet requests it from the API server, mounts it at a known path
  (/var/run/secrets/kubernetes.io/serviceaccount/token), and rotates
  it before expiry. The pod never manages credentials — the platform
  provides them.

  This is the same JWT format from Experiment 1, but the "user" is a
  workload (a pod), not a human.

  Workload OIDC token (real signed JWT):

  ${workloadToken}

  Decoded header:

  {
    "typ": "${workloadHeader.typ}",
        ↳ Standard JWT. The same token type from Experiment 1. OIDC
          tokens for workloads use the same format as tokens for humans.

    "alg": "${workloadHeader.alg}",
        ↳ ES256 = ECDSA with P-256. The cluster's IdP signs workload
          tokens with its private key, just like any OIDC provider.

    "kid": "${workloadHeader.kid}"
        ↳ Key ID. Points to the signing key in the cluster's JWKS.
          Same kid-based lookup from Experiment 6 — the cloud STS
          will fetch the cluster's JWKS and find this key to verify.
  }

  Decoded payload:

  {
    "iss": "${workloadPayload.iss}",
        ↳ Issuer. The cluster's OIDC discovery URL. The cloud STS
          uses this to find the cluster's JWKS endpoint at
          {iss}/.well-known/openid-configuration → jwks_uri.

    "sub": "${workloadPayload.sub}",
        ↳ Subject. The workload's identity — "system:serviceaccount"
          followed by namespace and service account name. This is the
          K8s-native identity string, not a human user ID.

    "aud": "${workloadPayload.aud}",
        ↳ Audience. Who this token is intended for — the cloud STS.
          The STS rejects tokens not addressed to it.

    "exp": ${workloadPayload.exp},
        ↳ Expiry. ${workloadPayload.exp - workloadPayload.iat} seconds (15 minutes) from issuance. Short-lived
          by design — the kubelet rotates the token at ~80% lifetime
          (about 12 minutes), so the pod always has a valid token.

    "iat": ${workloadPayload.iat},
        ↳ Issued At. When the kubelet requested this token.

    "nbf": ${workloadPayload.nbf},
        ↳ Not Before. Token is not valid before this time.

    "kubernetes.io": {
      "namespace": "${namespace}",
          ↳ K8s namespace. Scopes the workload identity — the same
            service account name in different namespaces is a
            different identity.

      "serviceaccount": {
        "name": "${serviceAccount}",
            ↳ ServiceAccount name. Combined with namespace, this is
              the workload's identity in the cluster.
        "uid": "${workloadPayload['kubernetes.io'].serviceaccount.uid}"
            ↳ Unique ID of the ServiceAccount object. Changes if the
              SA is deleted and recreated — prevents stale bindings.
      },

      "pod": {
        "name": "${podName}",
            ↳ The specific pod instance. Useful for audit — which
              exact replica made this request?
        "uid": "${workloadPayload['kubernetes.io'].pod.uid}"
            ↳ Pod UID. Unique to this pod instance.
      }
    }
  }

  The kubelet automatically:
    1. Requests a token from the K8s API server for the pod's SA
    2. Mounts it at /var/run/secrets/kubernetes.io/serviceaccount/token
    3. Rotates it at ~80% of TTL (~12 min for a 15-min token)
    4. The pod reads the file — always fresh, never expired

  No secrets stored. No credentials to leak. The platform provides
  the identity.

  🎯 INTERVIEW ALERT: "What is Workload Identity Federation?"
     WIF lets workloads authenticate to cloud services using
     platform-native OIDC tokens instead of static secrets. The cloud
     verifies the token against the workload's IdP JWKS — same JWT
     verification as Experiment 1.

  🎯 INTERVIEW ALERT: "What is the Secret Zero problem?"
     "I need a secret to get my secrets." Static credentials create a
     bootstrapping problem — how do you securely deliver the first
     credential? WIF solves it: the platform (kubelet, VM metadata
     service) attests the workload's identity. No stored secret needed.
`);
  await pause();

  // ── STEP 2: Token Exchange (STS) ──────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 2: Token Exchange — Cloud STS (RFC 8693)

  The workload has its OIDC token. Now it needs to access a cloud
  service (e.g., Cloud Storage). It presents the token to the cloud's
  Security Token Service (STS), which exchanges it for a short-lived
  cloud access token.

  RFC 8693 Token Exchange Request:

  POST ${stsUrl}/v1/token
  Content-Type: application/x-www-form-urlencoded

    grant_type=urn:ietf:params:oauth:grant-type:token-exchange
        ↳ RFC 8693 grant type. Tells the STS this is a token exchange,
          not a standard OAuth2 flow (authorization_code, client_credentials).

    subject_token_type=urn:ietf:params:oauth:token-type:jwt
        ↳ The incoming token is a JWT. The STS knows to parse and
          verify it as a signed JWT, not an opaque token.

    subject_token=${workloadToken.substring(0, 40)}...
        ↳ The workload's OIDC token. The full signed JWT from Step 1.

    requested_token_type=urn:ietf:params:oauth:token-type:access_token
        ↳ What the workload wants back — an access token for the
          target cloud API.

    audience=${targetApi}
        ↳ The target API the workload wants to access.

    scope=https://www.googleapis.com/auth/cloud-platform
        ↳ The permissions requested.

  The STS performs 5-step verification:`);
  console.log();

  // Step 1: Verify signature against cluster JWKS
  const clusterJwksVerifier = createLocalJWKSet(clusterJwks);
  const { payload: verifiedWorkload, protectedHeader: verifiedWorkloadHeader } =
    await jwtVerify(workloadToken, clusterJwksVerifier, {
      issuer: clusterIssuer,
      audience: stsUrl,
    });

  console.log(`    ✅ Step 1: Verify signature against cluster JWKS`);
  console.log(`       Fetched JWKS from ${clusterIssuer}/.well-known/openid-configuration`);
  console.log(`       Found key by kid "${verifiedWorkloadHeader.kid}"`);
  console.log(`       jose.jwtVerify() confirmed signature is valid`);
  console.log();

  // Step 2: Check issuer matches configured trust
  const issuerTrusted = verifiedWorkload.iss === clusterIssuer;
  console.log(`    ✅ Step 2: Check iss matches configured trust`);
  console.log(`       iss = "${verifiedWorkload.iss}"`);
  console.log(`       Matches configured Workload Identity Pool trust — ${issuerTrusted ? 'accepted' : 'rejected'}`);
  console.log();

  // Step 3: Check sub matches allowed service accounts
  const subAllowed = verifiedWorkload.sub === `system:serviceaccount:${namespace}:${serviceAccount}`;
  console.log(`    ✅ Step 3: Check sub matches allowed service accounts`);
  console.log(`       sub = "${verifiedWorkload.sub}"`);
  console.log(`       Matches IAM policy binding — ${subAllowed ? 'authorized' : 'denied'}`);
  console.log();

  // Step 4: Check aud is the STS
  const audCorrect = verifiedWorkload.aud === stsUrl;
  console.log(`    ✅ Step 4: Check aud is the STS`);
  console.log(`       aud = "${verifiedWorkload.aud}"`);
  console.log(`       Token was intended for this STS — ${audCorrect ? 'accepted' : 'rejected'}`);
  console.log();

  // Step 5: Issue short-lived cloud access token
  console.log(`    ✅ Step 5: Issue short-lived cloud access token`);
  console.log(`       Federated identity: ${federatedIdentity}`);
  console.log(`       TTL: 300 seconds (5 minutes)`);
  console.log(`       Target: ${targetApi}`);
  console.log();

  console.log(`  Token Exchange Response (RFC 8693):`);
  console.log();
  console.log(`  {`);
  console.log(`    "access_token": "${cloudAccessToken.substring(0, 40)}...",`);
  console.log(`        ↳ The short-lived cloud access token. A real signed JWT.`);
  console.log(`    "token_type": "Bearer",`);
  console.log(`    "expires_in": 300,`);
  console.log(`        ↳ 5 minutes. Even shorter than the workload token (15 min).`);
  console.log(`    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"`);
  console.log(`        ↳ Confirms the STS issued an access token (not a refresh token).`);
  console.log(`  }`);
  console.log();
  console.log(`  The workload can now call ${targetApi} with:`);
  console.log(`    Authorization: Bearer ${cloudAccessToken.substring(0, 30)}...`);
  console.log();
  console.log(`  No static API key. No service account JSON file. The workload's`);
  console.log(`  platform identity (K8s ServiceAccount) was exchanged for a`);
  console.log(`  short-lived cloud credential. When the cloud token expires in`);
  console.log(`  5 minutes, the workload repeats the exchange with a fresh`);
  console.log(`  workload token (which the kubelet keeps rotating).`);
  console.log();

  console.log(`  🎯 INTERVIEW ALERT: "How does token exchange work in WIF?"`);
  console.log(`     The workload presents its OIDC token to the cloud's STS. The`);
  console.log(`     STS verifies the signature against the cluster's JWKS, checks`);
  console.log(`     iss/sub/aud, and issues a short-lived cloud access token`);
  console.log(`     (RFC 8693). No static secrets anywhere in the flow.`);

  await pause();

  // ── STEP 3: Workload Identity Lab (Exploration Point) ─────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 3: Workload Identity Lab

  Five scenarios covering the full WIF landscape — from end-to-end
  GCP flows to SPIFFE, Secret Zero, and the capstone connection map.`);

  await explore('Pick a scenario to explore:', [
    {
      name: 'GCP WIF flow (end-to-end)',
      fn: async () => {
        console.log(`  GCP Workload Identity Federation — End-to-End Flow`);
        console.log();
        console.log(`  A K8s pod needs to read from Cloud Storage. No static API key,`);
        console.log(`  no service account JSON file. Here's the complete flow:`);
        console.log();
        console.log(`  ┌────────────────────────────────────────────────────────────┐`);
        console.log(`  │  1. Pod starts in namespace "${namespace}"                   │`);
        console.log(`  │     ServiceAccount: ${serviceAccount}                          │`);
        console.log(`  │     Pod: ${podName}                            │`);
        console.log(`  └────────────────────────────────────────────────────────────┘`);
        console.log(`                            │`);
        console.log(`                            ▼`);
        console.log(`  ┌────────────────────────────────────────────────────────────┐`);
        console.log(`  │  2. Kubelet projects OIDC token                           │`);
        console.log(`  │     Signs with cluster's private key (ES256)              │`);
        console.log(`  │     Mounts at /var/run/secrets/.../token                  │`);
        console.log(`  │     TTL: 15 min, auto-rotated at ~12 min                  │`);
        console.log(`  └────────────────────────────────────────────────────────────┘`);
        console.log(`                            │`);
        console.log(`                            ▼`);
        console.log(`  ┌────────────────────────────────────────────────────────────┐`);
        console.log(`  │  3. Pod reads token from volume mount                     │`);
        console.log(`  │     const token = fs.readFileSync(tokenPath, 'utf-8');    │`);
        console.log(`  └────────────────────────────────────────────────────────────┘`);
        console.log(`                            │`);
        console.log(`                            ▼`);
        console.log(`  ┌────────────────────────────────────────────────────────────┐`);
        console.log(`  │  4. Pod presents token to GCP STS                         │`);
        console.log(`  │     POST ${stsUrl}/v1/token                 │`);
        console.log(`  │     grant_type=token-exchange                             │`);
        console.log(`  │     subject_token=<OIDC JWT>                              │`);
        console.log(`  └────────────────────────────────────────────────────────────┘`);
        console.log(`                            │`);
        console.log(`                            ▼`);
        console.log(`  ┌────────────────────────────────────────────────────────────┐`);
        console.log(`  │  5. STS verifies against cluster JWKS                     │`);
        console.log(`  └────────────────────────────────────────────────────────────┘`);
        console.log();

        await pause();

        // Show the real workload JWT
        console.log(`  The workload's OIDC token (real signed JWT):`);
        console.log();
        console.log(`  ${workloadToken}`);
        console.log();

        const header = decodeProtectedHeader(workloadToken);
        console.log(`  Decoded header:`);
        console.log(`  { "typ": "${header.typ}", "alg": "${header.alg}", "kid": "${header.kid}" }`);
        console.log();
        console.log(`  Decoded payload:`);
        console.log(`  {`);
        console.log(`    "iss": "${workloadPayload.iss}",`);
        console.log(`    "sub": "${workloadPayload.sub}",`);
        console.log(`    "aud": "${workloadPayload.aud}",`);
        console.log(`    "exp": ${workloadPayload.exp} (${workloadPayload.exp - workloadPayload.iat}s TTL),`);
        console.log(`    "kubernetes.io": {`);
        console.log(`      "namespace": "${namespace}",`);
        console.log(`      "serviceaccount": { "name": "${serviceAccount}" },`);
        console.log(`      "pod": { "name": "${podName}" }`);
        console.log(`    }`);
        console.log(`  }`);
        console.log();

        await pause();

        // STS verification
        console.log(`  STS verification (5 steps):`);
        console.log();

        const verifier = createLocalJWKSet(clusterJwks);
        const { payload: vPayload, protectedHeader: vHeader } =
          await jwtVerify(workloadToken, verifier, {
            issuer: clusterIssuer,
            audience: stsUrl,
          });

        console.log(`    ✅ 1. Signature verified against cluster JWKS (kid: ${vHeader.kid})`);
        console.log(`    ✅ 2. Issuer "${vPayload.iss}" matches configured trust`);
        console.log(`    ✅ 3. Subject "${vPayload.sub}" is in allowed service accounts`);
        console.log(`    ✅ 4. Audience "${vPayload.aud}" is this STS`);
        console.log(`    ✅ 5. Issue short-lived cloud access token (5 min TTL)`);
        console.log();

        // Show issued cloud access token
        const cloudHeader = decodeProtectedHeader(cloudAccessToken);
        console.log(`  Issued cloud access token:`);
        console.log();
        console.log(`  ${cloudAccessToken}`);
        console.log();
        console.log(`  Decoded header:`);
        console.log(`  { "typ": "${cloudHeader.typ}", "alg": "${cloudHeader.alg}", "kid": "${cloudHeader.kid}" }`);
        console.log();
        console.log(`  Decoded payload:`);
        console.log(`  {`);
        console.log(`    "iss": "${cloudAccessPayload.iss}",`);
        console.log(`        ↳ Issued by the STS, not the cluster.`);
        console.log(`    "sub": "${cloudAccessPayload.sub}",`);
        console.log(`        ↳ Federated identity — maps the K8s SA to a cloud principal.`);
        console.log(`    "aud": "${cloudAccessPayload.aud}",`);
        console.log(`        ↳ Target API the workload can access.`);
        console.log(`    "exp": ${cloudAccessPayload.exp} (${cloudAccessPayload.exp - cloudAccessPayload.iat}s TTL),`);
        console.log(`        ↳ 5 minutes. Even shorter than the workload token.`);
        console.log(`    "scope": "${cloudAccessPayload.scope}"`);
        console.log(`        ↳ Permissions granted.`);
        console.log(`  }`);
        console.log();
        console.log(`  The pod can now call Cloud Storage:`);
        console.log(`    GET https://storage.googleapis.com/my-bucket/data.json`);
        console.log(`    Authorization: Bearer ${cloudAccessToken.substring(0, 30)}...`);
        console.log();

        console.log(`  🎯 INTERVIEW ALERT: "Why are short-lived workload tokens better than static API keys?"`);
        console.log(`     Short-lived tokens expire automatically, are rotated by the`);
        console.log(`     platform, can't be leaked long-term, and are cryptographically`);
        console.log(`     bound to the workload's identity.`);
      },
    },
    {
      name: 'SPIFFE/SVID',
      fn: async () => {
        console.log(`  SPIFFE — Secure Production Identity Framework for Everyone`);
        console.log();
        console.log(`  SPIFFE standardizes workload identity across platforms. Instead of`);
        console.log(`  platform-specific identity formats (K8s ServiceAccount, AWS IAM role,`);
        console.log(`  GCP service account), SPIFFE provides a universal identity scheme.`);
        console.log();
        console.log(`  SPIFFE ID Format:`);
        console.log();
        console.log(`    spiffe://<trust-domain>/<workload-path>`);
        console.log();
        console.log(`    Examples:`);
        console.log(`    ${spiffeId}`);
        console.log(`        ↳ trust-domain: ${spiffeTrustDomain}`);
        console.log(`          path: /ns/${namespace}/sa/${serviceAccount}`);
        console.log(`          Encodes namespace + service account in the path.`);
        console.log();
        console.log(`    spiffe://example.org/k8s/us-east1/payments/api`);
        console.log(`        ↳ Cluster + region + namespace + workload in the path.`);
        console.log(`          The path structure is up to the organization.`);
        console.log();
        console.log(`    spiffe://bank.internal/vm/prod/transaction-processor`);
        console.log(`        ↳ VM-based workload. SPIFFE isn't K8s-only.`);
        console.log();
        console.log(`  Trust Domains:`);
        console.log(`    A trust domain is a boundary of trust — all workloads within it`);
        console.log(`    share a common root of trust (CA or JWKS). Cross-domain`);
        console.log(`    communication requires federation between trust domains.`);
        console.log();

        await pause();

        console.log(`  SVID — SPIFFE Verifiable Identity Document`);
        console.log();
        console.log(`  An SVID is the proof of identity. Two forms:`);
        console.log(`    1. X.509 SVID — certificate with SPIFFE ID in the SAN (URI)`);
        console.log(`    2. JWT SVID — signed JWT with SPIFFE ID as the subject`);
        console.log();
        console.log(`  JWT SVID (real signed JWT):`);
        console.log();
        console.log(`  ${spiffeSvid}`);
        console.log();

        const svidHeader = decodeProtectedHeader(spiffeSvid);
        console.log(`  Decoded header:`);
        console.log(`  { "typ": "${svidHeader.typ}", "alg": "${svidHeader.alg}", "kid": "${svidHeader.kid}" }`);
        console.log();
        console.log(`  Decoded payload:`);
        console.log(`  {`);
        console.log(`    "iss": "${spiffeSvidPayload.iss}",`);
        console.log(`        ↳ Issuer is the trust domain. The SPIFFE runtime`);
        console.log(`          (e.g., SPIRE) signs SVIDs within its trust domain.`);
        console.log();
        console.log(`    "sub": "${spiffeSvidPayload.sub}",`);
        console.log(`        ↳ The SPIFFE ID. This IS the workload's identity —`);
        console.log(`          universal, platform-agnostic, verifiable.`);
        console.log();
        console.log(`    "aud": "${spiffeSvidPayload.aud}",`);
        console.log(`        ↳ The target workload's SPIFFE ID. The SVID is scoped`);
        console.log(`          to a specific peer — workload-to-workload auth.`);
        console.log();
        console.log(`    "exp": ${spiffeSvidPayload.exp}`);
        console.log(`        ↳ Short-lived. SPIRE rotates SVIDs automatically,`);
        console.log(`          similar to how kubelet rotates projected tokens.`);
        console.log(`  }`);
        console.log();

        await pause();

        // Verify the SVID
        console.log(`  Verifying the SVID:`);
        console.log();
        const svidVerifier = createLocalJWKSet(clusterJwks);
        const { payload: vSvid, protectedHeader: vSvidHeader } =
          await jwtVerify(spiffeSvid, svidVerifier);
        console.log(`    ✅ Signature verified (kid: ${vSvidHeader.kid})`);
        console.log(`    ✅ Subject: ${vSvid.sub}`);
        console.log(`    ✅ Audience: ${vSvid.aud}`);
        console.log(`    ✅ Trust domain: ${vSvid.iss}`);
        console.log();
        console.log(`  SPIFFE gives every workload a verifiable identity regardless of`);
        console.log(`  platform — K8s, VMs, bare metal, multi-cloud. The SVID is the`);
        console.log(`  proof. The SPIFFE ID is the name.`);
        console.log();

        console.log(`  🎯 INTERVIEW ALERT: "What is SPIFFE?"`);
        console.log(`     A standard for workload identity. Defines SPIFFE IDs`);
        console.log(`     (spiffe://trust-domain/path) and SVIDs (X.509 cert or JWT`);
        console.log(`     proving workload identity). Platform-agnostic — works across`);
        console.log(`     K8s, VMs, bare metal.`);
      },
    },
    {
      name: 'Secret Zero problem',
      fn: async () => {
        console.log(`  The Secret Zero Problem`);
        console.log();
        console.log(`  The anti-pattern: a chain of secrets that never bottoms out.`);
        console.log();
        console.log(`  ┌─────────────────────────────────────────────────────────────┐`);
        console.log(`  │  "My app needs a database password."                        │`);
        console.log(`  │                                                             │`);
        console.log(`  │  OK, store it in a secret manager (Vault, AWS Secrets       │`);
        console.log(`  │  Manager, GCP Secret Manager).                              │`);
        console.log(`  │                                                             │`);
        console.log(`  │  "But how does my app authenticate to the secret manager?"  │`);
        console.log(`  │                                                             │`);
        console.log(`  │  Use an API key or token.                                   │`);
        console.log(`  │                                                             │`);
        console.log(`  │  "But where do I store THAT API key?"                       │`);
        console.log(`  │                                                             │`);
        console.log(`  │  In an environment variable? A config file?                 │`);
        console.log(`  │                                                             │`);
        console.log(`  │  "But those can be leaked too..."                           │`);
        console.log(`  │                                                             │`);
        console.log(`  │  ∞ Infinite regress. There's always a "first secret" that   │`);
        console.log(`  │    must exist somewhere in plaintext.                        │`);
        console.log(`  └─────────────────────────────────────────────────────────────┘`);
        console.log();
        console.log(`  The root cause: static secrets require bootstrapping. You need`);
        console.log(`  a secret to get your secrets. That "Secret Zero" must be stored`);
        console.log(`  somewhere — and wherever it is, it can be leaked, stolen, or`);
        console.log(`  mismanaged.`);
        console.log();

        await pause();

        console.log(`  The WIF Solution: Platform-Attested Identity`);
        console.log();
        console.log(`  ┌─────────────────────────────────────────────────────────────┐`);
        console.log(`  │  "My app needs to access Cloud Storage."                    │`);
        console.log(`  │                                                             │`);
        console.log(`  │  The kubelet knows which pod you are (it started you).      │`);
        console.log(`  │  It signs an OIDC token attesting your identity.            │`);
        console.log(`  │                                                             │`);
        console.log(`  │  "But where's the secret?"                                  │`);
        console.log(`  │                                                             │`);
        console.log(`  │  There is no secret. The platform IS the attestation.       │`);
        console.log(`  │  The kubelet's signing key is the cluster's identity.        │`);
        console.log(`  │  The cloud trusts the cluster's JWKS. Done.                 │`);
        console.log(`  │                                                             │`);
        console.log(`  │  No API key. No token file. No environment variable.        │`);
        console.log(`  │  No Secret Zero.                                            │`);
        console.log(`  └─────────────────────────────────────────────────────────────┘`);
        console.log();
        console.log(`  How the chain breaks:`);
        console.log();
        console.log(`    Static secrets:  App → needs key → key stored where? → needs`);
        console.log(`                     key to access that → needs key to... (∞)`);
        console.log();
        console.log(`    WIF:             App → kubelet attests identity → OIDC token`);
        console.log(`                     → STS verifies against JWKS → cloud access`);
        console.log(`                     token. Chain terminates at platform attestation.`);
        console.log();
        console.log(`  Platform attestation examples:`);
        console.log(`    K8s:     Kubelet signs ServiceAccount OIDC token`);
        console.log(`    AWS:     Instance metadata service (IMDSv2) provides role creds`);
        console.log(`    GCP:     Metadata server provides identity token`);
        console.log(`    Azure:   IMDS provides managed identity token`);
        console.log(`    GitHub:  Actions runtime provides OIDC token for the workflow`);
        console.log();
        console.log(`  In every case: the platform knows who you are because it started`);
        console.log(`  you. No secret needed to prove it.`);
      },
    },
    {
      name: 'Token lifetimes and rotation',
      fn: async () => {
        console.log(`  Token Lifetimes and Rotation — Auto-Rotated vs Static`);
        console.log();
        console.log(`  K8s Projected Token: 15-minute TTL, kubelet rotates at 80%`);
        console.log();
        console.log(`  ──────────────────────────────────────────────────────────────`);
        console.log(`  PROJECTED TOKEN LIFECYCLE:`);
        console.log(`  ──────────────────────────────────────────────────────────────`);
        console.log();
        console.log(`  min 0       Token issued (TTL = 15 min)`);
        console.log(`              └─ Kubelet mounts at /var/run/secrets/.../token`);
        console.log();
        console.log(`  min 3       Pod reads token, exchanges for cloud access token`);
        console.log(`              └─ Cloud token: 5 min TTL. Pod caches it.`);
        console.log();
        console.log(`  min 8       Cloud token expires → pod re-reads workload token`);
        console.log(`              └─ Same workload token still valid. New exchange.`);
        console.log();
        console.log(`  min 12      Kubelet rotates workload token (80% of 15 min)`);
        console.log(`              └─ New token written to volume mount. Old token`);
        console.log(`                 still valid until min 15 (overlap window).`);
        console.log();
        console.log(`  min 13      Pod reads NEW token for next exchange`);
        console.log(`              └─ Seamless. Pod always reads from same path.`);
        console.log();
        console.log(`  min 15      Old token expires — but already replaced at min 12`);
        console.log(`              └─ No gap. No downtime. Continuous rotation.`);
        console.log();

        await pause();

        console.log(`  ──────────────────────────────────────────────────────────────`);
        console.log(`  STATIC API KEY LIFECYCLE:`);
        console.log(`  ──────────────────────────────────────────────────────────────`);
        console.log();
        console.log(`  day 0       API key created, stored in environment variable`);
        console.log(`              └─ Manually provisioned. No expiry.`);
        console.log();
        console.log(`  day 30      Key works fine. No rotation scheduled.`);
        console.log();
        console.log(`  day 90      Compliance asks: "when was the key last rotated?"`);
        console.log(`              └─ Never. It was created 90 days ago.`);
        console.log();
        console.log(`  day 120     Developer leaves company. Had access to the key.`);
        console.log(`              └─ Key still works. No automatic revocation.`);
        console.log();
        console.log(`  day 150     Key leaked in a log file.`);
        console.log(`              └─ Full access until someone notices and manually`);
        console.log(`                 rotates. Could be hours, days, weeks.`);
        console.log();
        console.log(`  day ???     Manual rotation finally happens.`);
        console.log(`              └─ Every service using this key breaks. Coordinated`);
        console.log(`                 update across all consumers. Downtime risk.`);
        console.log();

        await pause();

        // Decode workload token to show exp
        const parts = workloadToken.split('.');
        const wPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

        console.log(`  Concrete comparison from the tokens in this experiment:`);
        console.log();
        console.log(`  ┌──────────────────────┬──────────────────────────┬──────────────────────────┐`);
        console.log(`  │                      │  Projected Token (WIF)   │  Static API Key          │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  TTL                 │  ${wPayload.exp - wPayload.iat}s (15 min)            │  Never expires           │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Rotation            │  Automatic at ~80% TTL  │  Manual, coordinated     │`);
        console.log(`  │                      │  (~12 min). No downtime.│  downtime risk.           │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Leak impact         │  Usable for ≤15 min.    │  Usable until manually   │`);
        console.log(`  │                      │  Scoped to one pod.     │  revoked. Full access.   │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Identity binding    │  Cryptographically      │  None. Bearer token —    │`);
        console.log(`  │                      │  bound to K8s SA + pod. │  anyone with the key     │`);
        console.log(`  │                      │                         │  is "authorized".        │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Audit trail         │  iss/sub/pod claims     │  "API key XYZ was used"  │`);
        console.log(`  │                      │  identify exact workload│  — which workload? Who?  │`);
        console.log(`  └──────────────────────┴──────────────────────────┴──────────────────────────┘`);
      },
    },
    {
      name: 'Continue (full series connection map)',
      fn: async () => {
        console.log(`  Static Secrets vs Workload Identity Federation`);
        console.log();
        console.log(`  ┌──────────────────────┬──────────────────────────┬──────────────────────────┐`);
        console.log(`  │                      │  Static Secrets          │  WIF                     │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Bootstrapping       │  Secret Zero problem.   │  Platform attests         │`);
        console.log(`  │                      │  Need a secret to get   │  identity. No stored     │`);
        console.log(`  │                      │  your secrets.          │  secret needed.           │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Rotation            │  Manual. Coordinated    │  Automatic. Platform     │`);
        console.log(`  │                      │  across all consumers.  │  handles rotation.       │`);
        console.log(`  │                      │  Downtime risk.         │  No downtime.            │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Blast radius        │  Leaked key = full      │  Leaked token = ≤15 min  │`);
        console.log(`  │                      │  access until manually  │  of access. Scoped to    │`);
        console.log(`  │                      │  revoked.               │  one workload.           │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Audit               │  "Key X was used" —     │  JWT claims identify     │`);
        console.log(`  │                      │  no workload identity.  │  exact workload, pod,    │`);
        console.log(`  │                      │                         │  namespace.              │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Identity binding    │  None. Bearer token.    │  Cryptographically       │`);
        console.log(`  │                      │  Anyone with the key    │  bound to platform       │`);
        console.log(`  │                      │  is authorized.         │  identity (K8s SA).      │`);
        console.log(`  └──────────────────────┴──────────────────────────┴──────────────────────────┘`);
        console.log();

        await pause();

        console.log(`  Capstone: The 9-Experiment Connection Map`);
        console.log();
        console.log(`  Every experiment in this series connects. WIF (Experiment 9) is`);
        console.log(`  the capstone — it uses JWT format, JWKS verification, and token`);
        console.log(`  exchange to eliminate the last category of static secrets.`);
        console.log();
        console.log(`  ┌─────────────────────────────────────────────────────────────┐`);
        console.log(`  │                    THE IDENTITY STACK                       │`);
        console.log(`  ├─────────────────────────────────────────────────────────────┤`);
        console.log(`  │                                                             │`);
        console.log(`  │  Layer 1: Presence                                          │`);
        console.log(`  │  ┌───────────────────────┐  ┌───────────────────────┐       │`);
        console.log(`  │  │ Exp 3: WebAuthn        │  │ Exp 5: Passkeys       │       │`);
        console.log(`  │  │ Ceremony anatomy       │  │ Cross-device auth     │       │`);
        console.log(`  │  │ (human presence)       │  │ (discoverable creds)  │       │`);
        console.log(`  │  └───────────────────────┘  └───────────────────────┘       │`);
        console.log(`  │                                                             │`);
        console.log(`  │  Layer 2: Identity / Grant                                  │`);
        console.log(`  │  ┌───────────────────────┐  ┌───────────────────────┐       │`);
        console.log(`  │  │ Exp 1: OIDC Tokens     │  │ Exp 4: OAuth2 / PAR   │       │`);
        console.log(`  │  │ JWT anatomy, claims    │──│ Authorization flows   │       │`);
        console.log(`  │  │ (the foundation)       │  │ (grants & scopes)     │       │`);
        console.log(`  │  └───────────┬───────────┘  └───────────────────────┘       │`);
        console.log(`  │              │                                               │`);
        console.log(`  │  Layer 3: Binding                                            │`);
        console.log(`  │  ┌───────────┴───────────┐  ┌───────────────────────┐       │`);
        console.log(`  │  │ Exp 2: DPoP            │  │ Exp 6: JWKS Rotation  │       │`);
        console.log(`  │  │ Sender constraint      │──│ Key lifecycle, kid    │       │`);
        console.log(`  │  │ (token binding)        │  │ (trust infrastructure)│       │`);
        console.log(`  │  └───────────────────────┘  └───────────┬───────────┘       │`);
        console.log(`  │                                          │                   │`);
        console.log(`  │  Layer 4: Lifecycle                      │                   │`);
        console.log(`  │  ┌───────────────────────┐              │                   │`);
        console.log(`  │  │ Exp 7: SCIM            │              │                   │`);
        console.log(`  │  │ Provisioning/deprovisioning           │                   │`);
        console.log(`  │  │ (identity lifecycle)   │              │                   │`);
        console.log(`  │  └───────────┬───────────┘              │                   │`);
        console.log(`  │              │                            │                   │`);
        console.log(`  │  Layer 5: Enforcement                    │                   │`);
        console.log(`  │  ┌───────────┴───────────┐              │                   │`);
        console.log(`  │  │ Exp 8: CAEP            │              │                   │`);
        console.log(`  │  │ Real-time revocation   │              │                   │`);
        console.log(`  │  │ (enforcement signals)  │              │                   │`);
        console.log(`  │  └───────────────────────┘              │                   │`);
        console.log(`  │                                          │                   │`);
        console.log(`  │  Cross-cutting                           │                   │`);
        console.log(`  │  ┌───────────────────────────────────────┴─────────────┐     │`);
        console.log(`  │  │ Exp 9: Workload Identity Federation (THIS)          │     │`);
        console.log(`  │  │ Platform OIDC tokens (Exp 1) + JWKS verify (Exp 6) │     │`);
        console.log(`  │  │ + RFC 8693 token exchange → no static secrets       │     │`);
        console.log(`  │  └─────────────────────────────────────────────────────┘     │`);
        console.log(`  │                                                             │`);
        console.log(`  │  Connections:                                                │`);
        console.log(`  │    Exp 1 → 9: Same JWT format. Workload tokens ARE OIDC     │`);
        console.log(`  │               tokens — same header, claims, signing.        │`);
        console.log(`  │    Exp 2 → 9: DPoP sender-constrains human tokens. WIF      │`);
        console.log(`  │               platform-constrains workload tokens.          │`);
        console.log(`  │    Exp 3/5→ 9: WebAuthn proves human presence. WIF proves   │`);
        console.log(`  │               workload presence (platform attestation).     │`);
        console.log(`  │    Exp 4 → 9: OAuth2 issues grants for humans. RFC 8693     │`);
        console.log(`  │               exchanges tokens for workloads.               │`);
        console.log(`  │    Exp 6 → 9: JWKS rotation for IdPs. Cluster JWKS for WIF.│`);
        console.log(`  │               Same kid-based key lookup.                    │`);
        console.log(`  │    Exp 7 → 9: SCIM manages human lifecycle. WIF manages     │`);
        console.log(`  │               workload identity lifecycle.                  │`);
        console.log(`  │    Exp 8 → 9: CAEP signals for human sessions. WIF tokens   │`);
        console.log(`  │               are short-lived — revocation by expiry.       │`);
        console.log(`  │                                                             │`);
        console.log(`  └─────────────────────────────────────────────────────────────┘`);
        console.log();
        console.log(`  The through-line: identity is about proving who you are (human`);
        console.log(`  or workload) to systems that need to trust you, using standards`);
        console.log(`  that are interoperable, verifiable, and don't rely on shared`);
        console.log(`  secrets.`);
      },
    },
  ]);

  console.log();
  await pause();

  // ── Summary Card ────────────────────────────────────────────

  console.log(`${'═'.repeat(66)}
  SUMMARY CARD
  Cover the answers below. Try to answer each from memory.
${'═'.repeat(66)}

  Q: What is Workload Identity Federation?
  A: Workloads authenticate to cloud services using platform-native
     OIDC tokens instead of static secrets. Cloud verifies against
     workload IdP's JWKS.

  Q: What is the Secret Zero problem?
  A: "I need a secret to get my secrets." WIF eliminates this: the
     platform attests identity, no bootstrapping secret needed.

  Q: How does the STS exchange work?
  A: Workload OIDC token → STS verifies signature against cluster
     JWKS → checks iss/sub/aud → issues short-lived cloud access
     token (RFC 8693).

  Q: What is SPIFFE?
  A: Standard for workload identity. SPIFFE ID: spiffe://trust-domain/path.
     SVID: X.509 cert or JWT proving identity.

  Q: Static secrets vs WIF?
  A: Static: never expire, manual rotation, can be leaked, no identity
     binding. WIF: short-lived, auto-rotated, platform-attested, no
     secrets to steal.

${'═'.repeat(66)}
`);

  // ── Practice Prompt ─────────────────────────────────────────

  console.log(`  PRACTICE: Close this terminal. Explain out loud what Workload`);
  console.log(`  Identity Federation is, how the token exchange flow works (workload`);
  console.log(`  OIDC token → STS verification → short-lived cloud token), what the`);
  console.log(`  Secret Zero problem is and how WIF solves it, and why SPIFFE matters`);
  console.log(`  for workload identity. Then come back and check.`);
  console.log();

  close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
