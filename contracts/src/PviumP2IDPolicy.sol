// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IP2IDPolicy} from "./interfaces/IP2IDPolicy.sol";

/// @title PviumP2IDPolicy
/// @notice The launch policy for P2ID vaults: an owner-managed allowlist of verifiers, and no fee.
///         Later capabilities (permissionless verifier registration with a stake, protocol fees)
///         ship as a new policy that the vault factory switches to through its timelock; the
///         vaults and their addresses do not change.
/// @dev `owner` should be a Pvium multisig. Approving a verifier only lets payers opt into it;
///      revoking one freezes claims under it (refunds still work) and never moves funds.
contract PviumP2IDPolicy is IP2IDPolicy {
    address public owner;
    address public pendingOwner;
    mapping(address verifier => bool) public approvedVerifiers;

    event VerifierApprovalSet(address indexed verifier, bool approved);
    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);

    error NotOwner();
    error NotPendingOwner();
    error InvalidOwner();
    error InvalidVerifier();
    error NoFees();

    constructor(address _owner, address[] memory _verifiers) {
        if (_owner == address(0)) revert InvalidOwner();
        owner = _owner;
        emit OwnershipTransferred(address(0), _owner);
        for (uint256 i = 0; i < _verifiers.length; i++) _setApproval(_verifiers[i], true);
    }

    /// @notice Approve (or revoke) a verifier.
    function approveVerifier(address verifier, bool approved) external onlyOwner {
        _setApproval(verifier, approved);
    }

    /// @inheritdoc IP2IDPolicy
    function isVerifierAllowed(address verifier) external view returns (bool) {
        return approvedVerifiers[verifier];
    }

    /// @inheritdoc IP2IDPolicy
    function feeBps(address, address) external pure returns (uint16) {
        return 0;
    }

    /// @inheritdoc IP2IDPolicy
    /// @dev The launch policy charges no fee, so a vault never has fees for it to distribute.
    function distributeFee(address, address, uint256) external payable {
        revert NoFees();
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

    function _setApproval(address verifier, bool approved) private {
        if (approved && verifier.code.length == 0) revert InvalidVerifier();
        approvedVerifiers[verifier] = approved;
        emit VerifierApprovalSet(verifier, approved);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }
}
