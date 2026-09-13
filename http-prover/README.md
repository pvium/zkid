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

`GET /healthz` — liveness, no auth; reports `circuitVersion` and `vkHash`. Startup fails if the vk
on disk does not hash to what `circuit/version.json` says, so a half-synced deploy cannot serve.

## Running

```sh
yarn install
yarn sync          # copy circuit/target/pvium_identity.json and the vk from ../circuit
cp .env.example .env && $EDITOR .env
yarn build && yarn start        # node --env-file=.env dist/server.js
```

Requires the `bb` binary (`~/.bb/bb` by default, or `BB_BIN`) at the pinned version
`5.0.0-nightly.20260522`. Configuration is entirely through `.env`; see `.env.example`. `PRIVY_JWKS_URL` may list several
JWKS URLs, comma-separated, to trust more than one Privy app (production and sandbox, say) from one
process: the token's `kid` and signature pick the key, and the response's `kid` says which app it
was. Sandbox attestations still cannot verify against a production SDK or contract, because those
pin the production key.

### Sizing

One attestation takes about 8 s on a 14-core machine: ~3 s solving (single-threaded WASM) and ~5 s
proving (all cores, ~3 GB peak). Set `MAX_CONCURRENCY` to `floor(RAM / 3 GB)`; extra requests queue.
Solving blocks the Node event loop, so run two instances (see `ecosystem.config.cjs`) to keep
`/healthz` responsive.

### VPS with PM2

```sh
yarn global add pm2
pm2 start ecosystem.config.cjs && pm2 save && pm2 startup
```

### Docker

```sh
yarn sync && docker build -t pvium-prover .
docker run --env-file .env -p 8787:8787 --shm-size=1g pvium-prover
```

`WORK_DIR` defaults to `/dev/shm` in the image so witness files (which contain the token) never
touch disk.

## Deploying from CI

`.github/workflows/deploy-prover.yml` deploys over SSH on a `prover-v*` tag or a manual run, into
the GitHub environment `production`. Set that environment up with required reviewers and a tag rule
so a deploy always needs an approval, and add these environment secrets:

| Secret | Value |
| --- | --- |
| `VPS_HOST`, `VPS_USER` | host and a deploy-only user (needs `node`, `yarn`, `pm2`, and `bb` on PATH or `BB_BIN` in `.env`) |
| `VPS_PASSWORD` | that user's password (used via `sshpass`; a key would be better, see below) |
| `VPS_APP_DIR` | directory the service lives in; its `.env` is created by hand from `.env.example` and never touched by CI |

The workflow compiles the circuit (cached by source hash), checks the vk hash against
`circuit/version.json`, builds, rsyncs only runtime files, reloads PM2, and hits `/healthz`.
To move from a password to a key later: generate one (`ssh-keygen -t ed25519`), append the public
half to `~/.ssh/authorized_keys` on the VPS, store the private half as a secret, and swap the
`sshpass -e ssh` prefix in the workflow for `ssh -i`. Because the repo is public, keep the secrets in
the protected environment only, review every change
under `.github/` (see `CODEOWNERS`), and pin third-party actions to commit SHAs before relying on this.

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
