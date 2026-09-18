# P2ID vault review

Date: 2026-09-18. Scope: `P2IDVault`, `PviumP2IdVaultFactory`, `PviumP2IDPolicy`,
`PviumVerifier`, and the `PviumIdentity` integration in the working tree. This review covers
contract logic and trust boundaries; it is not a circuit or generated-verifier cryptography audit.

No unprivileged theft path was identified for standard, fixed-balance ERC-20 tokens under
honest verifiers and governance. The following recovery and trust assumptions need explicit
treatment before deployment. Production contracts were not modified.

## 1. Medium: default-verifier migration can restore a superseded wallet

Locations: `src/P2IDVault.sol:266`, `src/P2IDVault.sol:397`,
`src/PviumP2IdVaultFactory.sol:144`.

The vault stores `owner` and `latestProofIat` separately for each verifier. However, all
untracked funds follow the factory's current default verifier. Changing that default moves
the funds between independent recovery states without carrying forward the previous default's
freshness requirement.

Reproduction:

1. Verifiers A and B recognise the old wallet at issue time 1000.
2. The identity owner rotates to a new wallet and submits an A proof at time 2000. A now rejects
   the old proof.
3. Governance switches the default from A to B after the required delay.
4. Anyone calls `sweepUntracked`; B's old wallet receives the entire untracked balance.

The same outcome is possible if B is initially unset and accepts an older proof after the
switch. This requires B to accept the historical attestation, or already have its wallet
recorded; it does not assume forged ZK proofs. Overlapping signing-key sets, an attester-only
verifier replacement, or switching back to an earlier verifier can satisfy that condition.
If the old wallet is compromised, both existing and subsequent direct transfers are exposed
until recovery is also performed under B. Deposits explicitly pinned to A are unaffected.

Recommendation: define recovery continuity for default changes. One option is a separate
recovery state for direct transfers with an authenticated migration to the new verifier.
Another is immutable verifier binding for each address scheme. Do not simply share timestamps
across every allowed verifier: a malicious opt-in verifier could then lock unrelated buckets
by returning an arbitrarily large timestamp. Until resolved, recovery tooling must identify
and refresh every relevant verifier and monitor pending default changes.

## 2. Governance trust: direct transfers can be redirected or frozen

Locations: `src/PviumP2IdVaultFactory.sol:144`, `src/PviumP2IDPolicy.sol:36`,
`src/P2IDVault.sol:395`, `src/P2IDVault.sol:580`.

The vault trusts the selected verifier's returned wallet. Governance controlling verifier
approval and the factory can approve an arbitrary verifier, make it the default after the
timelock, and use it to route existing untracked funds to an arbitrary wallet. Recorded
deposits remain pinned to their original verifier. This is a privileged trust assumption,
not a permissionless bypass of `PviumVerifier` or an attack on the proof system.

Separately, the launch policy's owner can revoke the current default immediately, with no
factory proposal or delay. Direct transfers then have neither a claim path nor a refund path
until governance restores a working verifier. Recorded deposits retain their refund path.
Consequently, the factory timelock does not guarantee an uninterrupted exit window: revocation
can block claims while a replacement default is pending.

Recommendation: explicitly document that direct transfers trust governance for custody and
availability. If that trust is unacceptable, use immutable verifier binding or design an
exit path that governance cannot disable. Distinguish immediate allowlist changes from
timelocked policy replacement in operational documentation.

## 3. Token compatibility: balance contractions break deposit solvency

Locations: `src/P2IDVault.sol:508`, `src/P2IDVault.sol:522`, `src/P2IDVault.sol:563`.

Deposits and fees are accounted in fixed token units. The stated invariant
`balance >= trackedTotal + feesOwedTotal` depends on token behaviour: a negative rebase,
balance confiscation, or sender-side transfer surcharge can reduce the balance without a
matching reduction in liabilities. Incoming balance-delta accounting does not solve this.

The reproduction records two deposits of 100, models an external balance contraction from
200 to 150, and refunds the first deposit in full. The second deposit remains owed 100 but
only 50 remains, so its refund reverts. This is an integration limitation for affected tokens,
not an exploit against ordinary fixed-balance ERC-20s. The test models the contraction with
Hardhat storage mutation; it does not claim an attacker can modify a normal token's storage.

Recommendation: specify supported token semantics and reject unsupported tokens on recorded
funding paths if enforcement is required. Rebase support needs share-based accounting or a
wrapper. Direct transfers cannot be prevented, so their compatibility limits must also be
documented. The invariant should state its token assumptions.

## Verification

- Existing vault, fee, factory and real-proof verifier tests: **50 passed**.
- Added `test/P2IDVault.audit.test.ts`: **4 reproductions passed**, covering default migration,
  governance redirection, immediate revocation and balance contraction.
- Mock verifiers isolate vault state transitions; these reproductions do not establish a
  cryptographic forgery. Existing `PviumVerifier` tests exercise real proof verification.

Run from `contracts/`, with the repository's Node installation first on `PATH`:

```sh
yarn hardhat test test/P2IDVault.test.ts test/P2IDFees.test.ts test/PviumP2IdVaultFactory.test.ts test/PviumVerifier.test.ts test/P2IDVault.audit.test.ts
```

Other reviewed behaviours are intentional in the implementation: proof freshness is relative,
not an absolute expiry check; equal-time proofs can resolve different linked wallets for
constrained claims; claim/refund races after the refund window are first-transaction-wins;
and failed fee quotes waive the fee. These were not classified as new vulnerabilities.

## Resolution (2026-09-18)

1. **Fixed.** Direct transfers now have their own freshness floor, `P2IDVault.untrackedProofIat`:
   the newest proof presented through whichever verifier was the default at the time. It carries
   across default changes, and direct transfers are paid only to a default-verifier owner whose
   proof is at least that fresh. Only the default verifier can raise it, so an opt-in verifier
   cannot lock other buckets. The reproduction is now a regression test (`fixed (finding 1)` in
   `test/P2IDVault.audit.test.ts`), alongside a test that an opt-in verifier cannot raise the floor.
2. **Freeze fixed; rerouting mitigated and accepted as a documented trust assumption.** The vault
   now always honours the factory's current default verifier for claims, so a policy (or its
   owner) can no longer freeze direct transfers; it can still stop new deposits under it. A
   default-verifier change needs a fixed 14 days' notice (`DEFAULT_VERIFIER_DELAY`, in bytecode,
   separate from the 7-day policy delay), during which anyone can sweep. Governance can still
   route direct transfers through a verifier it chose after that notice; reproduced as a test.
3. **Accepted as a token assumption.** Tokens whose balances contract (negative rebase,
   confiscation, sender-side transfer tax) are unsupported; documented in `README.md`.
