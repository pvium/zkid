// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IP2IdVaultFactory} from "./interfaces/IP2IdVaultFactory.sol";
import {IP2IDPolicy} from "./interfaces/IP2IDPolicy.sol";
import {P2IDVault} from "./P2IDVault.sol";

/// @title PviumP2IdVaultFactory
/// @notice Deploys P2IDVaults with CREATE2, salted by identity hash, and points them at the
///         current policy (which verifiers are allowed, what capped fee applies) and default verifier. A vault takes no constructor arguments
///         (the factory calls `initialize` right after `new`), so its creation code is a constant
///         and an identity's vault address is
///         `keccak256(0xff ‖ factory ‖ identityHash ‖ keccak256(creationCode))`, computable
///         anywhere from two constants. Funds sent to that address before deployment are swept
///         by the owner after deployment (see P2IDVault: bare transfers are untracked and irrevocable).
/// @dev Everything expected to evolve is in the policy (IP2IDPolicy), so this factory and the vault
///      code, which fix every P2ID address, never have to change. Both move only through a
///      timelock (propose, wait, activate): the policy after `policyChangeDelay`, the default
///      verifier after DEFAULT_VERIFIER_DELAY, a fixed 14 days. Direct transfers follow the default
///      verifier and have no refund path, so a change to it gets the longer notice: anyone who
///      objects can sweep first, and the vault guarantees nothing can freeze their claim meanwhile.
///      What a policy can do is bounded by the vault (fee cap, fees fixed at funding, no fee on
///      refunds, never redirecting a payout, never blocking claims through the default verifier).
contract PviumP2IdVaultFactory is IP2IdVaultFactory {
    bytes32 public immutable nsHash;
    uint64 public immutable minRefundWindow;
    uint64 public immutable maxRefundWindow;

    /// @notice Proposes and activates policy / default-verifier changes (a Pvium multisig). Two-step transfer.
    address public owner;
    address public pendingOwner;

    /// @notice The policy every vault consults. Changes only via the timelock below.
    address public policy;
    /// @notice Verifier used when a payer does not choose one. Changes only via the timelock below.
    address public defaultVerifier;

    /// @notice Notice before a proposed default verifier can be activated. Fixed in this bytecode.
    uint64 public constant DEFAULT_VERIFIER_DELAY = 14 days;
    /// @notice Notice before a proposed policy can be activated.
    uint64 public immutable policyChangeDelay;
    address public proposedDefaultVerifier;
    /// @notice Earliest time the proposed default can be activated; 0 when nothing is proposed.
    uint64 public proposedDefaultEta;
    address public proposedPolicy;
    /// @notice Earliest time the proposed policy can be activated; 0 when nothing is proposed.
    uint64 public proposedPolicyEta;

    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);
    event DefaultVerifierProposed(address indexed verifier, uint64 eta);
    event DefaultVerifierProposalCancelled(address indexed verifier);
    event DefaultVerifierActivated(address indexed verifier);
    event PolicyProposed(address indexed policy, uint64 eta);
    event PolicyProposalCancelled(address indexed policy);
    event PolicyActivated(address indexed policy);

    error NotOwner();
    error NotPendingOwner();
    error InvalidOwner();
    error InvalidPolicy();
    error VerifierNotApproved(address verifier);
    error NothingProposed();
    error TimelockNotElapsed(uint64 eta);
    error InvalidRefundWindow();
    error TokenCallFailed();
    error TokenBalanceQueryFailed();
    error NothingReceived();

    constructor(
        address _owner,
        bytes32 _nsHash,
        address _policy,
        address _defaultVerifier,
        uint64 _policyChangeDelay,
        uint64 _minRefundWindow,
        uint64 _maxRefundWindow
    ) {
        if (_owner == address(0)) revert InvalidOwner();
        if (_minRefundWindow > _maxRefundWindow) revert InvalidRefundWindow();
        if (_policy.code.length == 0) revert InvalidPolicy();
        if (!IP2IDPolicy(_policy).isVerifierAllowed(_defaultVerifier)) revert VerifierNotApproved(_defaultVerifier);
        owner = _owner;
        emit OwnershipTransferred(address(0), _owner);
        nsHash = _nsHash;
        policyChangeDelay = _policyChangeDelay;
        minRefundWindow = _minRefundWindow;
        maxRefundWindow = _maxRefundWindow;
        policy = _policy;
        emit PolicyActivated(_policy);
        defaultVerifier = _defaultVerifier;
        emit DefaultVerifierActivated(_defaultVerifier);
    }

    // ------------------------------------------------------------------ policy (timelocked)

    /// @notice Announce a new policy. Takes effect only after `policyChangeDelay`, via
    ///         activatePolicy(). Replaces any pending policy proposal.
    function proposePolicy(address newPolicy) external onlyOwner {
        if (newPolicy.code.length == 0) revert InvalidPolicy();
        proposedPolicy = newPolicy;
        proposedPolicyEta = uint64(block.timestamp) + policyChangeDelay;
        emit PolicyProposed(newPolicy, proposedPolicyEta);
    }

    function cancelPolicyProposal() external onlyOwner {
        if (proposedPolicyEta == 0) revert NothingProposed();
        emit PolicyProposalCancelled(proposedPolicy);
        delete proposedPolicy;
        delete proposedPolicyEta;
    }

    /// @notice Switch every vault to the proposed policy once the delay has elapsed. The new policy
    ///         must allow the current default verifier, so bare transfers stay claimable.
    function activatePolicy() external onlyOwner {
        uint64 eta = proposedPolicyEta;
        if (eta == 0) revert NothingProposed();
        if (block.timestamp < eta) revert TimelockNotElapsed(eta);
        address newPolicy = proposedPolicy;
        if (!IP2IDPolicy(newPolicy).isVerifierAllowed(defaultVerifier)) revert VerifierNotApproved(defaultVerifier);
        delete proposedPolicy;
        delete proposedPolicyEta;
        policy = newPolicy;
        emit PolicyActivated(newPolicy);
    }

    // ------------------------------------------------------------------ default verifier (timelocked)

    /// @notice Announce a new default verifier (must be allowed by the policy). Takes effect only
    ///         after DEFAULT_VERIFIER_DELAY (14 days), via activateDefaultVerifier(). Replaces any
    ///         pending proposal.
    function proposeDefaultVerifier(address verifier) external onlyOwner {
        if (!IP2IDPolicy(policy).isVerifierAllowed(verifier)) revert VerifierNotApproved(verifier);
        proposedDefaultVerifier = verifier;
        proposedDefaultEta = uint64(block.timestamp) + DEFAULT_VERIFIER_DELAY;
        emit DefaultVerifierProposed(verifier, proposedDefaultEta);
    }

    function cancelDefaultVerifierProposal() external onlyOwner {
        if (proposedDefaultEta == 0) revert NothingProposed();
        emit DefaultVerifierProposalCancelled(proposedDefaultVerifier);
        delete proposedDefaultVerifier;
        delete proposedDefaultEta;
    }

    /// @notice Make the proposed verifier the default once the delay has elapsed. The policy must
    ///         still allow it (a revocation in the meantime cancels it in effect).
    function activateDefaultVerifier() external onlyOwner {
        uint64 eta = proposedDefaultEta;
        if (eta == 0) revert NothingProposed();
        if (block.timestamp < eta) revert TimelockNotElapsed(eta);
        address verifier = proposedDefaultVerifier;
        if (!IP2IDPolicy(policy).isVerifierAllowed(verifier)) revert VerifierNotApproved(verifier);
        delete proposedDefaultVerifier;
        delete proposedDefaultEta;
        defaultVerifier = verifier;
        emit DefaultVerifierActivated(verifier);
    }

    function transferOwnership(address to) external onlyOwner {
        pendingOwner = to;
        emit OwnershipTransferStarted(owner, to);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    // ------------------------------------------------------------------ vaults

    /// @inheritdoc IP2IdVaultFactory
    function vaultFor(bytes32 identityHash) public view returns (address) {
        return
            address(
                uint160(
                    uint256(
                        keccak256(
                            abi.encodePacked(
                                bytes1(0xff),
                                address(this),
                                identityHash,
                                initCodeHash()
                            )
                        )
                    )
                )
            );
    }

    /// @inheritdoc IP2IdVaultFactory
    function isDeployed(bytes32 identityHash) public view returns (bool) {
        return vaultFor(identityHash).code.length != 0;
    }

    /// @notice keccak256 of the P2IDVault creation code (no constructor arguments), for offline derivation.
    function initCodeHash() public pure returns (bytes32) {
        return keccak256(type(P2IDVault).creationCode);
    }

    /// @inheritdoc IP2IdVaultFactory
    function deploy(bytes32 identityHash) public returns (address vault) {
        vault = vaultFor(identityHash);
        if (vault.code.length != 0) return vault;
        P2IDVault v = new P2IDVault{salt: identityHash}();
        v.initialize(nsHash, identityHash, minRefundWindow, maxRefundWindow);
        vault = address(v);
        emit VaultDeployed(identityHash, vault);
    }

    /// @inheritdoc IP2IdVaultFactory
    function fund(
        bytes32 identityHash,
        address token,
        uint256 amount,
        bytes32 constraint,
        uint64 refundWindow
    ) external returns (address vault, uint256 depositId) {
        return
            _fund(
                identityHash,
                defaultVerifier,
                token,
                amount,
                constraint,
                refundWindow
            );
    }

    /// @inheritdoc IP2IdVaultFactory
    function fundWith(
        bytes32 identityHash,
        address verifier,
        address token,
        uint256 amount,
        bytes32 constraint,
        uint64 refundWindow
    ) external returns (address vault, uint256 depositId) {
        return
            _fund(
                identityHash,
                verifier,
                token,
                amount,
                constraint,
                refundWindow
            );
    }

    function _fund(
        bytes32 identityHash,
        address verifier,
        address token,
        uint256 amount,
        bytes32 constraint,
        uint64 refundWindow
    ) private returns (address vault, uint256 depositId) {
        vault = deploy(identityHash);
        // Collect from the payer (credit what actually arrived, for fee-on-transfer tokens),
        // then let the vault pull exactly that and record the payer as funder.
        uint256 before = _balanceOf(token);
        _callToken(
            token,
            abi.encodeWithSignature(
                "transferFrom(address,address,uint256)",
                msg.sender,
                address(this),
                amount
            )
        );
        uint256 received = _balanceOf(token) - before;
        if (received == 0) revert NothingReceived();
        _callToken(
            token,
            abi.encodeWithSignature("approve(address,uint256)", vault, received)
        );
        depositId = P2IDVault(vault).fundFor(
            msg.sender,
            verifier,
            token,
            received,
            constraint,
            refundWindow
        );
    }

    function _callToken(address token, bytes memory input) private {
        (bool ok, bytes memory data) = token.call(input);
        if (
            !ok ||
            (data.length != 0 &&
                (data.length != 32 || !abi.decode(data, (bool))))
        ) revert TokenCallFailed();
    }

    function _balanceOf(address token) private view returns (uint256 balance) {
        (bool ok, bytes memory data) = token.staticcall(
            abi.encodeWithSignature("balanceOf(address)", address(this))
        );
        if (!ok || data.length != 32) revert TokenBalanceQueryFailed();
        balance = abi.decode(data, (uint256));
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }
}
