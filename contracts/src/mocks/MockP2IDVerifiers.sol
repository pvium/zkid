// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IP2IDVerifier} from "../interfaces/IP2IDVerifier.sol";

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
}
