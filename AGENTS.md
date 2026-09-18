# Agent instructions for `circuits/`

Pvium zero-knowledge identity proofs: Noir circuit, attestation prover service, Node SDK, Solidity verifier.

## Package manager

**Use `yarn` for every JavaScript/TypeScript package in this repo. Never use `npm` or `npx`.**
Install with `yarn install`, run scripts with `yarn <script>`, run binaries with `yarn <bin>`
(e.g. `yarn hardhat test`). Commit `yarn.lock`; do not create `package-lock.json`.

## Toolchain on this machine

- **Node**: use the nvm install, not the Homebrew one (the Homebrew Node 15 at
  `/usr/local/bin/node` is broken and hangs). Put it first on `PATH` before any node/yarn command:
  `export PATH="$HOME/.nvm/versions/node/v24.15.0/bin:$PATH"`
- **Noir**: `nargo 1.0.0-beta.22` at `~/.nargo/bin`, paired with **Barretenberg**
  `bb 5.0.0-nightly.20260522` at `~/.bb`. These versions are pinned to each other; do not bump one
  without the other. `export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"`
- **Go**: `/usr/local/go/bin/go` (1.25) for a future `sdks/go`.
- **Python 3** is used only for `circuit/scripts/gen_prover.py`.

## Layout

| Folder | Contents |
| --- | --- |
| `circuit/` | Noir circuit (`src/`), witness generator (`scripts/`), e2e test + sample token/keys (`test/`) |
| `contracts/` | Hardhat 2 + ethers v6 project: generated Honk verifier, `PviumIdentity` (dev API), `P2IDVault` + `PviumVerifier`; `src/interfaces/`, `src/lib/PviumHash.sol` |
| `sdks/node/` | npm package `@pvium/zk-verifier` (bb.js verifier + claim decoding). `sdks/python`, `sdks/go` later |
| `http-prover/` | Attestation service (Express 5, `--env-file=.env`, noir_js solve, native `bb` prove). `yarn sync` copies circuit artifacts |

## Workflow rules

- `contracts/src/PviumZKVerifier.sol` (contract `PviumZKVerifier`, renamed from bb's `HonkVerifier` by the refresh script) is **generated** by `bb write_solidity_verifier`.
  Never hand-edit it. After any circuit change: `nargo compile`, `nargo execute`, `bb prove`,
  then `yarn fixtures` in `contracts/` to refresh test fixtures and the verifier, and `yarn sync`
  in `sdks/node/` to refresh its bundled vk and fixtures.
- **Circuit versioning**: `circuit/version.json` names the current build (`circuitVersion`, vk sha256).
  Bump `circuitVersion` whenever the compiled circuit changes, then sync all consumers (`yarn fixtures`
  in contracts, `yarn sync` in sdks/node and http-prover). Each consumer is pinned to one version:
  the SDK release embeds one vk and rejects other versions by name; the prover serves one version and
  echoes it in every attestation; `PviumIdentity` is deployed once per version. Old attestations stay
  valid against their own version's SDK release and contract; they are not regenerated in bulk.
- The Solidity sources in `contracts/src` are the source of truth; `sdks/node/scripts/sync-contracts.sh`
  copies them into the npm package at build time (gitignored there). Never edit `sdks/node/contracts/`.
- `http-prover/src/witness.ts` is a port of `circuit/scripts/gen_prover.py`; `http-prover/test/witness.test.ts`
  diffs their output byte for byte. Change both together. `@noir-lang/noir_js` in `http-prover/` is pinned
  to the nargo version (`1.0.0-beta.22`).
- Hash/normalisation rules must stay identical in four places: `circuit/src/main.nr` + `identity.nr`,
  `circuit/scripts/gen_prover.py`, `contracts/src/lib/PviumHash.sol`, `sdks/node/src/identity.ts`.
- `@aztec/bb.js` in `sdks/node` must be pinned to the same version as the installed `bb`
  (`5.0.0-nightly.20260522`): proofs and vks are not portable across versions.
- `P2ID.md` at the repo root is the protocol spec (address formula, identity type ids). The type
  table is append-only: never reassign or reuse an id; keep identity.nr, PviumHash.sol, the SDK
  and the prover in step and update P2ID.md with them.
- The identity-hash domain prefix is `p2id.identity.v1`. Prefixes are dot-separated
  (`p2id.<component>.vN`).
- Tests and their fixtures live in each package's `test/` folder (`circuit/test`, `contracts/test`).
  Sample token/keys are in `circuit/test/fixtures`; `contracts/test/fixtures` is a copy refreshed by
  `yarn fixtures`. Run `sh test/e2e.sh` in `circuit/` after changing the circuit or script.
- **Gate budget**: the circuit is ~1,147k gates, padded to 2^21 (1,048,576 was crossed on
  purpose when the wallet slot was added; proofs are generated offline at enrollment, so ~9 s /
  2.5 GB per proof is acceptable). The next ceiling is 2,097,152. Measure with
  `bb gates -b target/pvium_identity.json` after every circuit change.
- After a circuit change run `sh test/e2e.sh` and `sh test/adversarial.sh` in `circuit/` before
  re-proving; the adversarial suite is the regression test for the anchoring audit finding.
- Circuit compile and prove steps take one to several minutes; run them in the background and
  do not stack redundant runs.
- `circuit/test/fixtures/sample_token.jwt` is a real (expired) Privy identity token for a test user, with
  Privy's key in `privy_es256_public.pem`; `test_es256_*.pem` is a throwaway pair used only by the
  adversarial tests to sign decoy payloads.
