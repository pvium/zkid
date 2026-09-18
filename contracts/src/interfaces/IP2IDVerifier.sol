// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title IP2IDVerifier
/// @notice Use-case-agnostic identity verification: given a proof, return the wallet the proven
///         identity resolves to. Optionally also verify a funding constraint.
interface IP2IDVerifier {
    /// @notice A funding constraint and the evidence that it is satisfied.
    /// @param commitment bytes32(0) = no constraint; otherwise the commitment a deposit was funded with.
    /// @param signature  Evidence for `commitment`; for PviumVerifier, the registered signer's
    ///                   EIP-712 signature over Constraint(bytes32 commitment) in the verifier's
    ///                   domain. Empty when commitment is zero.
    struct Constraint {
        bytes32 commitment;
        bytes signature;
    }

    /// @param identityHash The identity the caller expects the proof to be for (e.g. the vault's
    ///                     commitment). Proofs are public once used on-chain, so the caller MUST
    ///                     pin the identity rather than trust whatever the submitted proof proves.
    /// @param proof        Opaque identity proof; the implementation defines the encoding.
    /// @param constraint   Skipped when `constraint.commitment == bytes32(0)`.
    /// @return wallet Wallet associated with the proven identity (never address(0)).
    /// @return iat    When the underlying attestation was issued (unix seconds).
    /// @dev MUST revert (never return address(0)) if the proof is invalid, is for a different
    ///      identity than `identityHash`, or the constraint is not satisfied.
    function getIdentityWallet(
        bytes32 identityHash,
        bytes calldata proof,
        Constraint calldata constraint
    ) external view returns (address wallet, uint64 iat);

    /// @notice Whether this verifier can ever satisfy a non-zero constraint. Vaults refuse
    ///         constrained deposits under a verifier that returns false (or does not implement
    ///         this), so a payer cannot lock funds behind a condition nobody can meet.
    function supportsConstraints() external view returns (bool);
}
