# http-prover

The Pvium attestation service. Given a user's Privy identity token, an identity on it, and a
linked wallet, it builds the witness, solves the circuit and produces the proof that
`@pvium/zk-verifier` and `PviumIdentity.sol` verify.

Runs as a small Express service behind a shared secret. Solving happens in-process with
`noir_js`; proving spawns the native `bb` binary. Nothing else is needed in the image.

## API

`POST /attestations` — `Authorization: Bearer <AUTH_TOKEN>`

```json
{ "identityType": "email", "identityValue": "you@example.com", "jwt": "<privy identity token>", "wallet": "0x…", "version": 1 }
```

Response, about 15 KB:

```json
{ "proof": "<base64>", "publicInputs": "<base64>", "wallet": "0x…", "identityType": "email", "issuedAt": 1789240094,
  "circuitVersion": 1, "vkHash": "0x…", "kid": "…" }
```

`version` is optional: omit it for the latest. A prover serves exactly one circuit version and
answers 400 for any other. The response always states the version used; store `circuitVersion`
with the attestation, because verifiers (the SDK release, the deployed contract) are each pinned
to one version and reject others. `issuedAt` is when Privy issued the token, the attestation time.

| Status | Meaning |
| --- | --- |
| 200 | attestation generated |
| 400 | malformed body, identity or wallet not linked in the token, token too large |
| 401 | bad secret, or the token is not signed by a trusted Privy key |
| 413 | body over 64 KB |
| 500 | solving or proving failed (logged without the token) |

Bad tokens are rejected in milliseconds by a native signature check before any proving starts.

### Asynchronous mode

Add `"callbackUrl": "https://your-backend/hooks/attestation?secret=…"` to the request and the
prover answers `202 { jobId, status: "queued" }` at once, then POSTs the outcome to that URL when
the proof is ready, about 8 s later:

```json
{ "jobId": "…", "status": "ok", "attestation": { … }, "identityType": "email", "identityValue": "…", "wallet": "0x…" }
{ "jobId": "…", "status": "error", "error": "no linked account with …", "identityType": "email", "identityValue": "…", "wallet": "0x…" }
```

The outcome is written to a SQLite outbox (`DB_PATH`, Node's built-in `node:sqlite`) *before* the
first delivery attempt, so a proof that has been paid for is never lost to a restart or a flaky
receiver. Delivery is retried with backoff (1 min, 5 min, 30 min, 2 h, then every 6 h) for up to
48 hours until your endpoint answers 2xx; a 4xx is treated as final. `GET /jobs/:id` (auth) returns
a job's delivery state and its result. Synchronous requests are not stored. The delivery is not signed: put a secret in the callback URL if you need to
authenticate it, and remember the attestation is independently verifiable anyway. Callback URLs
must be https unless `ALLOW_HTTP_CALLBACKS=true`. This is the mode to use from a login flow, where
nothing is waiting on the HTTP response and client timeouts do not apply.

### Back-pressure

Proves run at most `MAX_CONCURRENCY` at a time (about 3 GB each) and up to `MAX_QUEUE` requests wait
for a slot; beyond that, both modes get `503` with `Retry-After: 10` immediately rather than a
timeout later. `/healthz` reports `inFlight` and `queued`. Circuit solving runs in a worker thread,
so the HTTP loop stays responsive while proving; run a single PM2 instance (the memory gate is per
process).

`GET /healthz` — liveness, no auth; reports `circuitVersion`, `vkHash`, `inFlight`, `queued`, and
outbox job counts by status.

`GET /jobs/:id` — auth; a callback job's status (`pending` / `delivered` / `failed`), attempts, last
error, and its result (the attestation or the error that was delivered). Startup fails if the vk
on disk does not hash to what `circuit/version.json` says, so a half-synced deploy cannot serve.

## Running

```sh
yarn install
yarn sync          # copy circuit/target/pvium_identity.json and the vk from ../circuit
cp .env.example .env && $EDITOR .env
yarn build && yarn start        # node --env-file=.env dist/server.js
```

Requires a 64-bit Linux with glibc 2.34 or newer (Ubuntu 22.04+, Debian 12+; the `bb` binary
will not run on Ubuntu 20.04), Node 22.13+ (for `node:sqlite`) and the `bb` binary (`~/.bb/bb` by default, or `BB_BIN`) at the pinned version
`5.0.0-nightly.20260522`. Configuration is entirely through `.env`; see `.env.example`. `PRIVY_JWKS_URL` may list several
JWKS URLs, comma-separated, to trust more than one Privy app (production and sandbox, say) from one
process: the token's `kid` and signature pick the key, and the response's `kid` says which app it
was. Sandbox attestations still cannot verify against a production SDK or contract, because those
pin the production key.

### Sizing

One attestation takes about 8 s on a 14-core machine: ~3 s solving (single-threaded WASM) and ~5 s
proving (all cores, ~3 GB peak). Set `MAX_CONCURRENCY` to `floor(RAM / 3 GB)`; up to `MAX_QUEUE` extra requests wait, the rest get 503.
Solving runs in a worker thread, so one instance (see `ecosystem.config.cjs`) stays responsive.

### VPS with PM2

```sh
yarn global add pm2
pm2 start ecosystem.config.cjs && pm2 save && pm2 startup
```

### Railway

Set the service's **Root Directory** to `/http-prover` (and Watch Paths to `/http-prover/**`);
`railway.json` selects the Dockerfile builder and the `/healthz` check. Add a volume mounted at
`/app/data` for the outbox, set the variables from `.env.example` (`WORK_DIR`, `DB_PATH`,
`CIRCUIT_JSON`, `VK_PATH` are preset by the image), and give the service at least 4 GB of memory.
The circuit artifacts in `circuit/` are committed for exactly this reason: the build context is this
folder alone, and the image must contain the circuit it serves. `pvium_identity.json.gz` is the
compiled circuit stripped of source maps (4.6 MB); the service inflates it on first start. After a
circuit change, `yarn sync` and commit the updated `.gz`, `vk` and `version.json` with the version
bump.

### Docker

```sh
yarn sync && docker build -t pvium-prover .
docker run --env-file .env -p 8787:8787 --shm-size=1g -v prover-data:/app/data pvium-prover
```

`WORK_DIR` defaults to `/dev/shm` in the image so witness files (which contain the token) never
touch disk.

## Deploying from CI

`.github/workflows/deploy-prover.yml` deploys over SSH on a `prover-v*` tag or a manual run, into
the GitHub environment `production`. Set that environment up with required reviewers and a tag rule
so a deploy always needs an approval, and add these environment secrets:

| Secret | Value |
| --- | --- |
| `VPS_HOST`, `VPS_USER` | host and a deploy-only user (needs `node` >= 22.13, `yarn`, `pm2`; `bb` is installed by the deploy into `~/.bb` if missing) |
| `VPS_PASSWORD` | that user's password (used via `sshpass`; a key would be better, see below) |
| `VPS_APP_DIR` | directory the service lives in; its `.env` is created by hand from `.env.example` and never touched by CI |

The workflow compiles the circuit (cached by source hash), checks the vk hash against
`circuit/version.json`, builds, rsyncs only runtime files, reloads PM2, and hits `/healthz`.
To move from a password to a key later: generate one (`ssh-keygen -t ed25519`), append the public
half to `~/.ssh/authorized_keys` on the VPS, store the private half as a secret, and swap the
`sshpass -e ssh` prefix in the workflow for `ssh -i`. Because the repo is public, keep the secrets in
the protected environment only, review every change
under `.github/` (see `CODEOWNERS`), and pin third-party actions to commit SHAs before relying on this.

## Logging

One line per request on stdout, plus one per callback delivery attempt:

```
2026-09-14T10:00:00.000Z POST /attestations 202 14ms ip=203.0.113.7 mode=async type=email wallet=0x… job=3f2c…
2026-09-14T10:00:09.100Z job 3f2c… ok type=email wallet=0x… callback=api.example.com delivery=delivered
```

The token and the identity value are never logged. PM2 and Railway both collect stdout; on a VPS
install `pm2-logrotate` to cap file sizes.

## Security notes

- The token is a bearer credential for the user's Privy session. It is never logged, and the
  temp directory holding the witness is deleted after every job.
- The secret is compared in constant time.
- Whoever holds a valid token can request an attestation for any linked wallet of that user, so
  the service should only be reachable from your backend.

## Development

```sh
yarn test
```

Tests check the TypeScript witness builder against `circuit/scripts/gen_prover.py` byte for byte on
the real sample token, exercise the HTTP layer, and (when `bb` and the circuit artifacts are
present) generate a real attestation and verify it with `@pvium/zk-verifier`.
