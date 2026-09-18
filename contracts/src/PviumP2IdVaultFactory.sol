// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IP2IdVaultFactory} from "./interfaces/IP2IdVaultFactory.sol";
import {P2IDVault} from "./P2IDVault.sol";

/// @title PviumP2IdVaultFactory
/// @notice Deploys P2IDVaults with CREATE2, salted by identity hash, and keeps the registry of
///         verifiers a payer may fund a deposit under. A vault takes no constructor arguments
///         (the factory calls `initialize` right after `new`), so its creation code is a constant
///         and an identity's vault address is
///         `keccak256(0xff ‖ factory ‖ identityHash ‖ keccak256(creationCode))`, computable
///         anywhere from two constants. Funds sent to that address before deployment are swept
///         by the owner after deployment (see P2IDVault: bare transfers are untracked and irrevocable).
/// @dev Verifiers are added to the registry, never replaced: each deposit records the verifier it
///      was funded under and stays claimable through it (while approved) or refundable. Pvium's
///      own verifiers are immutable per (circuit version, Privy key), so a rotation or a new
///      circuit is a new verifier registered here. The default verifier (used by fund() and for
///      bare transfers) moves only through a timelock: propose, wait `defaultChangeDelay`,
///      activate. A compromised owner can therefore add verifiers payers must opt into, revoke
///      verifiers (freezing claims, never moving funds), or announce a default change that stays
///      visible on chain for the whole delay before it takes effect.
contract PviumP2IdVaultFactory is IP2IdVaultFactory {
    bytes32 public immutable nsHash;
    uint64 public immutable minRefundWindow;
    uint64 public immutable maxRefundWindow;

    /// @notice Admin of the verifier registry (a Pvium multisig). Two-step transfer.
    address public owner;
    address public pendingOwner;

    /// @notice Verifier used when a payer does not choose one. Changes only via the timelock below.
    address public defaultVerifier;
    mapping(address verifier => bool) public approvedVerifiers;

    /// @notice Delay between proposing a new default verifier and being able to activate it.
    uint64 public immutable defaultChangeDelay;
    address public proposedDefaultVerifier;
    /// @notice Earliest time the proposed default can be activated; 0 when nothing is proposed.
    uint64 public proposedDefaultEta;

    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);
    event DefaultVerifierProposed(address indexed verifier, uint64 eta);
    event DefaultVerifierProposalCancelled(address indexed verifier);
    event DefaultVerifierActivated(address indexed verifier);

    error NotOwner();
    error NotPendingOwner();
    error InvalidOwner();
    error InvalidVerifier();
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
        address _defaultVerifier,
        uint64 _defaultChangeDelay,
        uint64 _minRefundWindow,
        uint64 _maxRefundWindow
    ) {
        if (_owner == address(0)) revert InvalidOwner();
        if (_minRefundWindow > _maxRefundWindow) revert InvalidRefundWindow();
        owner = _owner;
        emit OwnershipTransferred(address(0), _owner);
        nsHash = _nsHash;
        defaultChangeDelay = _defaultChangeDelay;
        minRefundWindow = _minRefundWindow;
        maxRefundWindow = _maxRefundWindow;
        _approveVerifier(_defaultVerifier, true);
        defaultVerifier = _defaultVerifier;
        emit DefaultVerifierActivated(_defaultVerifier);
    }

    // ------------------------------------------------------------------ registry (owner)

    /// @notice Approve (or revoke) a verifier. Revoking freezes claims on deposits funded under it
    ///         until it is re-approved; those deposits stay refundable.
    function approveVerifier(
        address verifier,
        bool approved
    ) external onlyOwner {
        _approveVerifier(verifier, approved);
    }

    /// @notice Announce a new default verifier (must be approved). Takes effect only after
    ///         `defaultChangeDelay`, via activateDefaultVerifier(). Replaces any pending proposal.
    function proposeDefaultVerifier(address verifier) external onlyOwner {
        if (!approvedVerifiers[verifier]) revert VerifierNotApproved(verifier);
        proposedDefaultVerifier = verifier;
        proposedDefaultEta = uint64(block.timestamp) + defaultChangeDelay;
        emit DefaultVerifierProposed(verifier, proposedDefaultEta);
    }

    function cancelDefaultVerifierProposal() external onlyOwner {
        if (proposedDefaultEta == 0) revert NothingProposed();
        emit DefaultVerifierProposalCancelled(proposedDefaultVerifier);
        delete proposedDefaultVerifier;
        delete proposedDefaultEta;
    }

    /// @notice Make the proposed verifier the default once the delay has elapsed. The proposal
    ///         must still be approved (a revocation in the meantime cancels it in effect).
    function activateDefaultVerifier() external onlyOwner {
        uint64 eta = proposedDefaultEta;
        if (eta == 0) revert NothingProposed();
        if (block.timestamp < eta) revert TimelockNotElapsed(eta);
        address verifier = proposedDefaultVerifier;
        if (!approvedVerifiers[verifier]) revert VerifierNotApproved(verifier);
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

    function _approveVerifier(address verifier, bool approved) private {
        if (verifier.code.length == 0) revert InvalidVerifier();
        approvedVerifiers[verifier] = approved;
        emit VerifierApprovalSet(verifier, approved);
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
