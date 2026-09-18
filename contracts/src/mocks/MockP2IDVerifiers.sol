// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IP2IDVerifier} from "../interfaces/IP2IDVerifier.sol";
import {IP2IDPolicy} from "../interfaces/IP2IDPolicy.sol";

/// @dev Test stub: proof = abi.encode(address wallet, bytes32 identityHash, uint64 iat).
///      A constraint is "satisfied" when its signature equals the bytes "ok".
contract MockIdentityVerifier is IP2IDVerifier {
    error MockIdentityMismatch();
    error MockConstraintFailed();

    function getIdentityWallet(bytes32 identityHash, bytes calldata proof, Constraint calldata constraint)
        external
        pure
        returns (address wallet, uint64 iat)
    {
        bytes32 proven;
        (wallet, proven, iat) = abi.decode(proof, (address, bytes32, uint64));
        if (proven != identityHash) revert MockIdentityMismatch();
        if (constraint.commitment != bytes32(0) && keccak256(constraint.signature) != keccak256("ok")) {
            revert MockConstraintFailed();
        }
    }

    function supportsConstraints() external pure virtual returns (bool) {
        return true;
    }
}

/// @dev Same, but declares it cannot satisfy constraints (like a PviumVerifier with no attester).
contract MockNoConstraintVerifier is MockIdentityVerifier {
    function supportsConstraints() external pure override returns (bool) {
        return false;
    }
}

interface IERC20Min {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @dev Test policy with adjustable allowlist, fee rate and distribution, and failure modes.
///      distributeFee pulls `pullBps` of the amount and splits it: `operatorShareBps` to the
///      operator registered for the verifier, the rest to `recipient` (the protocol).
contract MockFeePolicy is IP2IDPolicy {
    mapping(address => bool) public allowed;
    uint16 public bps;
    address public recipient;
    mapping(address verifier => address) public operatorOf;
    uint16 public operatorShareBps;
    uint16 public pullBps = 10_000;
    /// 0 = normal, 1 = fee calls revert, 2 = fee calls burn all gas, 3 = distributeFee reverts,
    /// 4 = distributeFee tries to pull more than it was offered
    uint8 public mode;

    function allow(address verifier, bool ok) external {
        allowed[verifier] = ok;
    }

    function setFee(uint16 _bps, address _recipient) external {
        bps = _bps;
        recipient = _recipient;
    }

    function setMode(uint8 _mode) external {
        mode = _mode;
    }

    function isVerifierAllowed(address verifier) external view returns (bool) {
        return allowed[verifier];
    }

    function feeBps(address, address) external view returns (uint16) {
        _misbehave();
        return bps;
    }

    function setOperator(address verifier, address operator, uint16 shareBps) external {
        operatorOf[verifier] = operator;
        operatorShareBps = shareBps;
    }

    function setPullBps(uint16 _pullBps) external {
        pullBps = _pullBps;
    }

    function distributeFee(address verifier, address token, uint256 amount) external {
        if (mode == 3) revert("distribution down");
        uint256 pull = mode == 4 ? amount + 1 : (amount * pullBps) / 10_000;
        IERC20Min(token).transferFrom(msg.sender, address(this), pull);
        uint256 toOperator = operatorOf[verifier] == address(0) ? 0 : (pull * operatorShareBps) / 10_000;
        if (toOperator != 0) IERC20Min(token).transfer(operatorOf[verifier], toOperator);
        IERC20Min(token).transfer(recipient, pull - toOperator);
    }

    function _misbehave() private view {
        if (mode == 1) revert("policy down");
        if (mode == 2) {
            uint256 x;
            while (true) x++; // runs out of gas, never returns
        }
    }
}
