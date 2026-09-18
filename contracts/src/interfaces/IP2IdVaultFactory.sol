// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title IP2IdVaultFactory
/// @notice Deploys one P2IDVault per identity at an address anyone can derive offline from the
///         identity hash, and keeps the registry of verifiers a payer may fund a deposit under.
interface IP2IdVaultFactory {
    event VaultDeployed(bytes32 indexed identityHash, address indexed vault);
    event VerifierApprovalSet(address indexed verifier, bool approved);

    // ---- verifier registry (owner-managed) ----
    /// @notice Whether deposits may be funded under, and claimed through, `verifier`.
    function approvedVerifiers(address verifier) external view returns (bool);
    /// @notice Verifier used when a payer does not choose one, and the one bare transfers are claimed
    ///         through. Changes only through a timelocked proposal (see the factory).
    function defaultVerifier() external view returns (address);

    // ---- vaults ----
    /// @notice The vault address for `identityHash`, deployed or not:
    ///         `keccak256(0xff ‖ factory ‖ identityHash ‖ keccak256(P2IDVault creationCode))`.
    function vaultFor(bytes32 identityHash) external view returns (address);
    function isDeployed(bytes32 identityHash) external view returns (bool);
    /// @notice Deploy the vault for `identityHash`; returns the existing one if already deployed.
    function deploy(bytes32 identityHash) external returns (address vault);
    /// @notice Deploy if needed, then fund under the default verifier on the caller's behalf
    ///         (caller keeps the refund right). Approve this factory once to pay any identity.
    function fund(
        bytes32 identityHash,
        address token,
        uint256 amount,
        bytes32 constraint,
        uint64 refundWindow
    ) external returns (address vault, uint256 depositId);
    /// @notice Same, under a chosen approved verifier.
    function fundWith(
        bytes32 identityHash,
        address verifier,
        address token,
        uint256 amount,
        bytes32 constraint,
        uint64 refundWindow
    ) external returns (address vault, uint256 depositId);
}
