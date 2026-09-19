// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title P2IDHash
/// @notice The identity commitment exactly as circuit/src/main.nr computes it:
///         sha256("p2id.identity.v1" || identityType || normalize(value)).
///         `normalize` ASCII-lowercases every type except phone and wallet, and lowercases
///         `0x…` (EVM, hex) wallet addresses; base58 (Solana) addresses are untouched.
library P2IDHash {
    bytes internal constant PREFIX = "p2id.identity.v1";
    uint8 internal constant PHONE = 1;
    uint8 internal constant WALLET = 12;
    uint8 internal constant NUM_TYPES = 13;

    error ValueLength(uint256 length);
    error UnknownIdentityType(uint8 identityType);

    /// @notice Commitment for an identity value, e.g. (0, "you@example.com").
    function identityHash(uint8 identityType, bytes memory value) internal pure returns (bytes32) {
        if (identityType >= NUM_TYPES) revert UnknownIdentityType(identityType);
        if (value.length == 0 || value.length > 128) revert ValueLength(value.length);
        return sha256(abi.encodePacked(PREFIX, identityType, normalize(identityType, value)));
    }

    /// @notice Commitment for an EVM wallet, hashed as its lowercase `0x…` hex string.
    function walletHash(address wallet) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(PREFIX, WALLET, toLowerHex(wallet)));
    }

    /// @notice Commitment for a wallet on any chain, given as Privy stores it (e.g. base58).
    function walletHash(string memory wallet) internal pure returns (bytes32) {
        return identityHash(WALLET, bytes(wallet));
    }

    function normalize(uint8 identityType, bytes memory value) internal pure returns (bytes memory) {
        bool lower;
        if (identityType == WALLET) {
            lower = value.length >= 2 && value[0] == "0" && value[1] == "x";
        } else {
            lower = identityType != PHONE;
        }
        if (!lower) return value;
        bytes memory out = new bytes(value.length);
        for (uint256 i = 0; i < value.length; i++) {
            uint8 c = uint8(value[i]);
            out[i] = (c >= 65 && c <= 90) ? bytes1(c + 32) : value[i];
        }
        return out;
    }

    /// @dev "0x" + 40 lowercase hex chars, the form the circuit hashes an EVM address in.
    function toLowerHex(address a) internal pure returns (bytes memory out) {
        bytes16 digits = "0123456789abcdef";
        out = new bytes(42);
        out[0] = "0";
        out[1] = "x";
        uint160 v = uint160(a);
        for (uint256 i = 41; i > 1; i--) {
            out[i] = digits[v & 0xf];
            v >>= 4;
        }
    }
}
