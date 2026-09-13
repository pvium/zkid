// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IVerifier} from "./PviumIdentityVerifier.sol";
import {IPviumIdentity} from "./IPviumIdentity.sol";
import {PviumHash} from "./PviumHash.sol";

/// @title PviumIdentity
/// @notice On-chain verifier for Pvium attestations. Deployed once per chain by Pvium with the
///         Honk verifier and the P-256 key Privy signs the Pvium app's tokens with. Developers
///         call it through IPviumIdentity.
/// @dev Public input layout emitted by circuit/src/main.nr:
///        [0] identity_type   [1] recipient
///        [2] signer_x_hi     [3] signer_x_lo     [4] signer_y_hi   [5] signer_y_lo
///        [6] iat             [7] identity_hash_hi  [8] identity_hash_lo
///        [9] wallet_hash_hi  [10] wallet_hash_lo  (zero when the proof carries no wallet)
///      Hashes and coordinates are split into two 128-bit halves because a 256-bit value does
///      not fit in one BN254 field element.
contract PviumIdentity is IPviumIdentity {
    uint256 public constant PUBLIC_INPUT_COUNT = 11;

    IVerifier public immutable verifier;
    /// @notice Circuit version this deployment verifies (see circuit/version.json). One deployment per version.
    uint16 public immutable circuitVersion;
    /// @notice Registered signer public key, uncompressed P-256 coordinates.
    uint256 public immutable signerX;
    uint256 public immutable signerY;

    /// @notice Everything an attestation asserts, for Pvium's own contracts (e.g. escrow claims
    ///         that need `recipient`). Developers should use the IPviumIdentity functions.
    struct Attestation {
        uint8 identityType;
        /// Address bound into the proof by the prover (a claim recipient), or zero.
        address recipient;
        /// When Privy issued the token (unix seconds). Freshness policy is the caller's.
        uint64 iat;
        bytes32 identityHash;
        /// PviumHash.walletHash of a wallet linked in the same token, or 0.
        bytes32 walletHash;
    }

    error InvalidProof();
    error UnknownSigner(bytes32 x, bytes32 y);
    error WrongPublicInputCount(uint256 got);
    error InvalidPublicKey();
    error InvalidCircuitVersion();
    error IdentityTypeMismatch(uint8 expected, uint8 got);
    error IdentityMismatch();
    error NoWallet();
    error WalletMismatch();

    constructor(IVerifier _verifier, uint16 _circuitVersion, uint256 _signerX, uint256 _signerY) {
        if (!_isOnCurve(_signerX, _signerY)) revert InvalidPublicKey();
        if (_circuitVersion == 0) revert InvalidCircuitVersion();
        verifier = _verifier;
        circuitVersion = _circuitVersion;
        signerX = _signerX;
        signerY = _signerY;
    }

    // ---- developer-facing ---------------------------------------------------------------

    /// @inheritdoc IPviumIdentity
    function verifyIdentity(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        uint8 identityType,
        bytes calldata identityValue,
        address wallet
    ) external view returns (uint64 issuedAt) {
        return _verifyIdentity(
            proof, publicInputs, identityType, PviumHash.identityHash(identityType, identityValue), PviumHash.walletHash(wallet)
        );
    }

    /// @inheritdoc IPviumIdentity
    function verifyIdentityNonEvm(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        uint8 identityType,
        bytes calldata identityValue,
        string calldata wallet
    ) external view returns (uint64 issuedAt) {
        return _verifyIdentity(
            proof, publicInputs, identityType, PviumHash.identityHash(identityType, identityValue), PviumHash.walletHash(wallet)
        );
    }

    /// @inheritdoc IPviumIdentity
    function verifyIdentityHashes(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        uint8 identityType,
        bytes32 identityHash,
        bytes32 walletHash
    ) external view returns (uint64 issuedAt) {
        return _verifyIdentity(proof, publicInputs, identityType, identityHash, walletHash);
    }

    // ---- lower level ----------------------------------------------------------------------

    /// @notice Verify a proof and return everything it asserts. Reverts unless the proof is valid
    ///         and was produced from a token signed by the registered key.
    function verifyAttestation(bytes calldata proof, bytes32[] calldata publicInputs)
        public
        view
        returns (Attestation memory a)
    {
        a = _decode(publicInputs);
        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();
    }

    // ---- internals -----------------------------------------------------------------------

    function _verifyIdentity(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        uint8 identityType,
        bytes32 identityHash,
        bytes32 walletHash
    ) internal view returns (uint64) {
        Attestation memory a = _decode(publicInputs);
        if (a.identityType != identityType) revert IdentityTypeMismatch(identityType, a.identityType);
        if (a.identityHash != identityHash) revert IdentityMismatch();
        if (a.walletHash == bytes32(0)) revert NoWallet();
        if (a.walletHash != walletHash) revert WalletMismatch();
        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();
        return a.iat;
    }

    /// @dev Cheap checks first (layout, signer), so bad requests fail before the 4M-gas verify.
    function _decode(bytes32[] calldata publicInputs) internal view returns (Attestation memory a) {
        if (publicInputs.length != PUBLIC_INPUT_COUNT) revert WrongPublicInputCount(publicInputs.length);
        bytes32 x = _join(publicInputs[2], publicInputs[3]);
        bytes32 y = _join(publicInputs[4], publicInputs[5]);
        if (uint256(x) != signerX || uint256(y) != signerY) revert UnknownSigner(x, y);
        a.identityType = uint8(uint256(publicInputs[0]));
        a.recipient = address(uint160(uint256(publicInputs[1])));
        a.iat = uint64(uint256(publicInputs[6]));
        a.identityHash = _join(publicInputs[7], publicInputs[8]);
        a.walletHash = _join(publicInputs[9], publicInputs[10]);
    }

    function _join(bytes32 hi, bytes32 lo) internal pure returns (bytes32) {
        return bytes32((uint256(hi) << 128) | uint256(lo));
    }

    /// @dev y^2 == x^3 - 3x + b (mod p) on NIST P-256. Guards against registering a typo.
    function _isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
        uint256 p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
        uint256 b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
        if (x >= p || y >= p) return false;
        uint256 lhs = mulmod(y, y, p);
        uint256 rhs = addmod(addmod(mulmod(mulmod(x, x, p), x, p), p - mulmod(3, x, p), p), b, p);
        return lhs == rhs;
    }
}
