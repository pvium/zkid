// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IP2IDVerifier} from "./IP2IDVerifier.sol";

/// @title IP2IDVault
/// @notice A vault holding ERC-20 funds for one identity until its owner proves it and sweeps.
///         Every deposit names the verifier whose proofs can release it; the factory's policy
///         decides which verifiers are allowed and what (capped) fee applies.
interface IP2IDVault {
    /// @dev Field order packs into 5 storage slots:
    ///      [funder, fundedAt, consumed] [token, refundWindow] [verifier, feeBps] [amount] [constraint].
    struct Deposit {
        address funder;
        uint64 fundedAt;
        bool consumed;
        address token;
        uint64 refundWindow;
        address verifier;
        /// Fee rate fixed when the deposit was made (<= MAX_FEE_BPS); charged only on a claim.
        uint16 feeBps;
        uint128 amount;
        bytes32 constraint;
    }

    // ------------------------------------------------------------------ events
    // Every deposit is Funded once and then either Refunded (by its funder) or Claimed by a sweep.
    // Sweeps also emit one aggregate event with the net amount paid and the fee.

    /// @notice A deposit was recorded via fund()/fundWith()/fundFor().
    event Funded(uint256 indexed depositId, address indexed funder, address indexed token, uint256 amount, address verifier, bytes32 constraint, uint64 refundWindow, uint16 feeBps);
    /// @notice An unconsumed deposit was returned to its funder after its refund window (never charged a fee).
    event Refunded(uint256 indexed depositId, address indexed funder, address indexed token, uint256 amount);
    /// @notice A deposit was paid out by a sweep: `amount` gross, of which `fee` accrued as a fee.
    event Claimed(uint256 indexed depositId, address indexed to, uint256 amount, uint256 fee);
    /// @notice A proof newer than any seen under `verifier` set that verifier's owner wallet; older proofs are now refused.
    event OwnerRefreshed(address indexed verifier, address indexed owner, uint64 iat);
    /// @notice Default-bucket funds under `verifier` were paid to its owner wallet (`amount` net of `fee`).
    event Swept(address indexed verifier, address indexed token, uint256 amount, uint256 fee, address indexed to, uint256 depositsConsumed);
    /// @notice Funds from a constrained bucket were paid to the wallet the proof resolved to (`amount` net of `fee`).
    event SweptBucket(address indexed verifier, bytes32 indexed constraint, address indexed token, uint256 amount, uint256 fee, address to, uint256 depositsConsumed);
    /// @notice A fee accrued for `verifier`; it stays in the vault until withdrawFees() hands it to the policy.
    event FeeAccrued(address indexed verifier, address indexed token, uint256 amount);
    /// @notice The policy pulled `amount` of accrued fees to distribute.
    event FeesDistributed(address indexed verifier, address indexed token, uint256 amount, address policy);

    // setup (factory only, once)
    function initialize(bytes32 nsHash, bytes32 saltCommitment, uint64 minRefundWindow, uint64 maxRefundWindow) external;

    // funding
    /// @notice Fund under the factory's default verifier.
    function fund(address token, uint256 amount, bytes32 constraint, uint64 refundWindow) external returns (uint256 depositId);
    /// @notice Fund under any verifier the factory's policy allows.
    function fundWith(address verifier, address token, uint256 amount, bytes32 constraint, uint64 refundWindow) external returns (uint256 depositId);
    /// @notice Factory-only: record a deposit owned by `funder`; tokens are pulled from the factory.
    function fundFor(address funder, address verifier, address token, uint256 amount, bytes32 constraint, uint64 refundWindow) external returns (uint256 depositId);
    function refund(uint256 depositId) external;

    // proofs
    /// @notice Present a proof under `verifier` without claiming: sets that verifier's owner wallet
    ///         if the proof is newer than anything seen under it, and retires older proofs.
    function refreshProof(address verifier, bytes calldata proof) external;
    function refreshProofAndSweep(address verifier, bytes calldata proof, address token, uint256 depositCountLimit) external returns (uint256 amount, uint256 consumed);

    // claiming (amounts returned are net of fees)
    /// @notice Sweep `verifier`'s default bucket to its owner; the default verifier's sweep also takes untracked funds.
    function sweep(address verifier, address token, uint256 depositCountLimit) external returns (uint256 amount, uint256 consumed);
    function sweepUntracked(address token) external returns (uint256 amount);
    function sweepDeposits(address verifier, address token, uint256[] calldata depositIds) external returns (uint256 amount);
    function sweepBucket(address verifier, IP2IDVerifier.Constraint calldata constraint, address token, bytes calldata proof, uint256 depositCountLimit) external returns (uint256 amount, uint256 consumed);
    function sweepBucketDeposits(address verifier, IP2IDVerifier.Constraint calldata constraint, address token, uint256[] calldata depositIds, bytes calldata proof) external returns (uint256 amount);

    // fees
    /// @notice Hand the fees earned through `verifier` in `token` to the current policy to distribute. Anyone may call it.
    function withdrawFees(address verifier, address token) external returns (uint256 amount);

    // views
    function MAX_FEE_BPS() external view returns (uint16);
    function factory() external view returns (address);
    function policy() external view returns (address);
    function defaultVerifier() external view returns (address);
    function owner(address verifier) external view returns (address);
    function latestProofIat(address verifier) external view returns (uint64);
    /// @notice Freshness floor for direct transfers, carried across default-verifier changes.
    function untrackedProofIat() external view returns (uint64);
    function saltCommitment() external view returns (bytes32);
    function depositCount() external view returns (uint256);
    function bucketDepositIds(address verifier, bytes32 constraint, address token) external view returns (uint256[] memory);
    function bucketDepositCount(address verifier, bytes32 constraint, address token) external view returns (uint256);
    function bucketTotal(address verifier, bytes32 constraint, address token) external view returns (uint256);
    function trackedTotal(address token) external view returns (uint256);
    function feesOwed(address verifier, address token) external view returns (uint256);
    function feesOwedTotal(address token) external view returns (uint256);
    /// @notice Gross amount `sweep(verifier, token, 0)` would release now, before fees.
    function sweepable(address verifier, address token) external view returns (uint256);
    function untrackedBalance(address token) external view returns (uint256);
}
