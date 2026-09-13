// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title IPviumIdentity
/// @notice Verify a Pvium attestation on chain: "identity X and wallet W belong to the same
///         Privy user". Every function reverts unless the proof is valid, was made from a token
///         signed by the registered key, and binds exactly the values given. The return value is
///         when Privy issued that token (unix seconds); freshness policy is the caller's.
interface IPviumIdentity {
    /// @notice Circuit version this deployment verifies. Attestations state theirs; use the matching deployment.
    function circuitVersion() external view returns (uint16);

    /// @param identityType  Privy account type id: 0 email, 3 twitter_oauth, 5 github_oauth, … (see identity.nr)
    /// @param identityValue The identity as the user linked it, e.g. "you@example.com". Case does not matter.
    /// @param wallet        The EVM wallet the attestation binds.
    function verifyIdentity(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        uint8 identityType,
        bytes calldata identityValue,
        address wallet
    ) external view returns (uint64 issuedAt);

    /// @notice Same, for a wallet on another chain, given as Privy stores it (e.g. a base58 Solana address).
    function verifyIdentityNonEvm(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        uint8 identityType,
        bytes calldata identityValue,
        string calldata wallet
    ) external view returns (uint64 issuedAt);

    /// @notice Same, with the identity and wallet already hashed (PviumHash), for callers who must
    ///         not put the raw identity in calldata.
    function verifyIdentityHashes(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        uint8 identityType,
        bytes32 identityHash,
        bytes32 walletHash
    ) external view returns (uint64 issuedAt);
}
