// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IP2IDVerifier} from "./IP2IDVerifier.sol";

/// @title IP2IDVault
/// @notice A vault holding ERC-20 funds for one identity until its owner proves it and sweeps.
///         Every deposit names the verifier (from the factory's approved registry) whose proofs
///         can release it, so anyone can build a verifier for Pvium users to claim through.
interface IP2IDVault {
    /// @dev Field order packs into 5 storage slots:
    ///      [funder, fundedAt, consumed] [token, refundWindow] [verifier] [amount] [constraint].
    struct Deposit {
        address funder;
        uint64 fundedAt;
        bool consumed;
        address token;
        uint64 refundWindow;
        address verifier;
        uint128 amount;
        bytes32 constraint;
    }

    // ------------------------------------------------------------------ events
    // Every deposit is Funded once and then either Refunded (by its funder) or consumed by a
    // sweep. Sweeps emit one aggregate event per call with the total paid and the number of
    // deposits consumed; a default-verifier sweep also includes any untracked (bare-transfer) surplus.

    /// @notice A deposit was recorded via fund()/fundWith()/fundFor().
    event Funded(uint256 indexed depositId, address indexed funder, address indexed token, uint256 amount, address verifier, bytes32 constraint, uint64 refundWindow);
    /// @notice An unconsumed deposit was returned to its funder after its refund window.
    event Refunded(uint256 indexed depositId, address indexed funder, address indexed token, uint256 amount);
    /// @notice A proof newer than any seen under `verifier` set that verifier's owner wallet; older proofs are now refused.
    event OwnerRefreshed(address indexed verifier, address indexed owner, uint64 iat);
    /// @notice Default-bucket funds under `verifier` were paid to its owner wallet.
    event Swept(address indexed verifier, address indexed token, uint256 amount, address indexed to, uint256 depositsConsumed);
    /// @notice Funds from a constrained bucket were paid to the wallet the proof resolved to.
    event SweptBucket(address indexed verifier, bytes32 indexed constraint, address indexed token, uint256 amount, address to, uint256 depositsConsumed);

    // setup (factory only, once)
    function initialize(bytes32 nsHash, bytes32 saltCommitment, uint64 minRefundWindow, uint64 maxRefundWindow) external;

    // funding
    /// @notice Fund under the factory's default verifier.
    function fund(address token, uint256 amount, bytes32 constraint, uint64 refundWindow) external returns (uint256 depositId);
    /// @notice Fund under any verifier approved by the factory.
    function fundWith(address verifier, address token, uint256 amount, bytes32 constraint, uint64 refundWindow) external returns (uint256 depositId);
    /// @notice Factory-only: record a deposit owned by `funder`; tokens are pulled from the factory.
    function fundFor(address funder, address verifier, address token, uint256 amount, bytes32 constraint, uint64 refundWindow) external returns (uint256 depositId);
    function refund(uint256 depositId) external;

    // proofs
    /// @notice Present a proof under `verifier` without claiming: sets that verifier's owner wallet
    ///         if the proof is newer than anything seen under it, and retires older proofs.
    function refreshProof(address verifier, bytes calldata proof) external;
    function refreshProofAndSweep(address verifier, bytes calldata proof, address token, uint256 depositCountLimit) external returns (uint256 amount, uint256 consumed);

    // claiming
    /// @notice Sweep `verifier`'s default bucket to its owner; the default verifier's sweep also takes untracked funds.
    function sweep(address verifier, address token, uint256 depositCountLimit) external returns (uint256 amount, uint256 consumed);
    function sweepUntracked(address token) external returns (uint256 amount);
    function sweepDeposits(address verifier, address token, uint256[] calldata depositIds) external returns (uint256 amount);
    function sweepBucket(address verifier, IP2IDVerifier.Constraint calldata constraint, address token, bytes calldata proof, uint256 depositCountLimit) external returns (uint256 amount, uint256 consumed);
    function sweepBucketDeposits(address verifier, IP2IDVerifier.Constraint calldata constraint, address token, uint256[] calldata depositIds, bytes calldata proof) external returns (uint256 amount);

    // views
    function factory() external view returns (address);
    function defaultVerifier() external view returns (address);
    function owner(address verifier) external view returns (address);
    function latestProofIat(address verifier) external view returns (uint64);
    function saltCommitment() external view returns (bytes32);
    function depositCount() external view returns (uint256);
    function bucketDepositIds(address verifier, bytes32 constraint, address token) external view returns (uint256[] memory);
    function bucketDepositCount(address verifier, bytes32 constraint, address token) external view returns (uint256);
    function bucketTotal(address verifier, bytes32 constraint, address token) external view returns (uint256);
    function trackedTotal(address token) external view returns (uint256);
    function sweepable(address verifier, address token) external view returns (uint256);
    function untrackedBalance(address token) external view returns (uint256);
}
