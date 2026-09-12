# circuit — `pvium_identity`

Noir circuit proving that a [Privy identity token](https://docs.privy.io) contains a
linked account (email, GitHub handle, wallet, …) whose value hashes to a public commitment,
without revealing the token or the value.

Toolchain: `nargo 1.0.0-beta.22`, `bb 5.0.0-nightly.20260522` (install with `noirup -v 1.0.0-beta.22`
and `bbup -v 5.0.0-nightly.20260522`).

## Sample token

`test/fixtures/sample_token.jwt` is a **real Privy identity token** (test user, expired) and
`privy_es256_public.pem` is the matching key from Privy's JWKS
(`https://auth.privy.io/api/v1/apps/<app-id>/jwks.json`). `sample_payload.json` is its decoded
payload. `test_es256_private.pem` / `test_es256_public.pem` are a throwaway pair used only by
`test/adversarial.sh` to sign decoy payloads, since we cannot sign with Privy's key. Regenerate the witness from it with:

```sh
python3 scripts/gen_prover.py --jwt "$(cat test/fixtures/sample_token.jwt)" --pubkey test/fixtures/privy_es256_public.pem --type email --value test-9988@privy.io
```

## Two accounts per proof: identity + wallet

Besides the identity account, the proof can carry a second, optional `wallet` account from the
same token (`--wallet 0x…` in the witness script; `wallet_value_len = 0` leaves it empty). Both
objects must sit inside the same signed `linked_accounts` string, so the proof states "identity X
and wallet W belong to the same Privy user" — the fact Pvium's resolution API needs to make
trustless. `wallet_hash` uses the identity-hash formula with type 12, and is zero when unused.

## What is proven

Given a JWT signing input `base64url(header) "." base64url(payload)`:

1. `jwt_hash = sha256(signing_input)` — the exact digest Privy signed with ES256 — and
   `ecdsa_secp256r1::verify_signature(signer_x, signer_y, signature, jwt_hash)` holds.
   The signer's raw public key is exposed as public outputs so a verifier compares it against
   the key it trusts; the digest itself stays private.
2. The payload segment base64url-decodes to JSON. A string-boundary scan (escape-aware) marks
   every byte as inside or outside a JSON string; `"iat":<n>` must be outside
   any string, so a decoy inside a stringified claim such as `custom_metadata` cannot be used.
3. The `linked_accounts` string contains one flat object `{…}` with
   `\"type\":\"<type>\"` and `\"<key>\":\"<value>\"`, where `<type>`/`<key>` are fixed by
   `identity_type` (see the table in [src/identity.nr](src/identity.nr)).
4. `identity_hash = sha256("p2id.identity.v1" || identity_type_byte || normalize(value))` where
   `normalize` is ASCII lowercase for every type except `wallet`, plus lowercase for `0x…`
   (EVM, hex) wallet addresses; base58 Solana addresses are left as-is. The string prefix is a
   domain separator; bump it if the preimage layout ever changes.

Only member-boundary matches count: each key must be preceded by `{` or `,`, and escaped-quote
patterns can only occur inside the `linked_accounts` string, so a value cannot be forged from
another claim. Nested braces are rejected so type and value must come from the same account.

## Interface

| Name | Kind | Meaning |
| --- | --- | --- |
| `identity_type` | public input (u8) | Id from `identity.nr` (0 = email, 5 = github_oauth, 12 = wallet, …) |
| `recipient` | public input (Field) | Unconstrained; binds e.g. the claim address to the proof |
| `signature` | private | ES256 `r ‖ s` from the token, **normalised to low-s** (see below) |
| `signer_x`, `signer_y` | private | P-256 public key coordinates the token was signed with |
| `signer_x_hi/lo`, `signer_y_hi/lo` | public output | those coordinates, each split into two 128-bit halves |
| `iat` | public output (u64) | Token issued-at: when Privy attested the claim. Freshness policy belongs to the verifier |
| `identity_hash_hi/lo` | public output | Commitment to (type, value), split into two 128-bit halves |
| `linked_accounts_idx` | private | index of the top-level `"linked_accounts":"` key; the account object must lie inside that string |
| `wallet_acct_start`, `wallet_acct_end`, `wallet_type_idx`, `wallet_value_idx`, `wallet_value_len` | private | offsets of the optional wallet account (`--wallet`); all zero when unused |
| `wallet_hash_hi/lo` | public output | `sha256(prefix ‖ 12 ‖ normalize(address))` for that wallet, or zero |

Everything else (`signing_input`, indexes into the decoded payload, `value_len`) is private.
Public inputs are ordered `identity_type, recipient, signer_x_hi, signer_x_lo, signer_y_hi, signer_y_lo, iat,
identity_hash_hi, identity_hash_lo, wallet_hash_hi, wallet_hash_lo` (11 fields) for the Solidity verifier.

## Limits

| Constant | Value | Notes |
| --- | --- | --- |
| `MAX_B64_LEN` | 8000 | base64url payload chars; the sample token with 8 accounts uses 2023 |
| `MAX_PAYLOAD_LEN` | 6000 | decoded payload bytes |
| `MAX_HEADER_B64_LEN` | 128 | Privy's header (`alg`, `typ`, `kid`) encodes to 106 |
| `MAX_VALUE_LEN` | 128 | identity value bytes |

Circuit size with these limits: ~265k ACIR opcodes / ~855k UltraHonk gates. Cost is roughly
linear in `MAX_B64_LEN`; shrink it if browser proving time matters and users have few wallets.

## Build, run, prove

```sh
nargo compile
nargo test          # unit tests in src/
sh test/e2e.sh          # solve the circuit on the sample token and check its public outputs
sh test/adversarial.sh  # decoy payloads signed with the fixture key must fail to solve

# Build Prover.toml from a real Privy token and the app's verification key …
python3 scripts/gen_prover.py --jwt "$PRIVY_ID_TOKEN" --pubkey privy_verification_key.pem --type email --value you@example.com --wallet 0xYourLinkedWallet
# … or from the sample token signed with the throwaway test key
python3 scripts/gen_prover.py --jwt "$(cat test/fixtures/sample_token.jwt)" --pubkey test/fixtures/privy_es256_public.pem --type github_oauth --value dephizee

nargo execute witness            # prints the public outputs; compare with the script's "expected" block
bb prove -b target/pvium_identity.json -w target/witness.gz -t evm --write_vk --verify -o target/proof
bb write_solidity_verifier -k target/proof/vk -o ../contracts/src/PviumIdentityVerifier.sol
```

## Anchoring (audit fix)

Every prover-supplied offset is checked against the string-boundary scan:

- `linked_accounts_idx` must be outside any string and read `"linked_accounts":"`.
- Every byte from the start of that string value through `acct_end` must be inside a string, so
  the account object cannot come from any other claim. The only other place escaped
  `\"type\":\"...` patterns can occur is inside a different stringified claim
  (`custom_metadata`), and that is a different string.
- `iat_idx` must be outside any string.

`test/adversarial.sh` signs a payload with the fixture key that carries a decoy email object and a
decoy `iat` in `custom_metadata`, then feeds the circuit offsets pointing at them; each must fail.
This models a compromised Pvium backend injecting metadata into a user's token.

## Low-s signatures

ECDSA signatures are malleable: `(r, s)` and `(r, n - s)` are both valid. Barretenberg's
in-circuit verifier accepts only the low-s form (`s <= n/2`), and JWT libraries do not
normalise, so **every prover must replace `s` with `n - s` when `s > n/2`** before building
the witness. `gen_prover.py` does this in `normalize_low_s`; the TS and Go provers must too.

## Verifier-side checks (outside the circuit)

- Compare `(signer_x, signer_y)` against the Privy app's verification key. The signature is
  already verified in-circuit.
- A maximum age on `iat`: the circuit reports when Privy attested the claim and enforces nothing.
- `recipient == msg.sender` (or the intended beneficiary).
- Derive the routing address from `identity_hash` (e.g. as a CREATE2 salt) and compute it the
  same way on the payer side: lowercase the value for every type except `wallet`, prepend the
  type byte and the `p2id.identity.v1` prefix, SHA-256.
