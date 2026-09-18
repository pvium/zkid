// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IP2IDVerifier} from "./interfaces/IP2IDVerifier.sol";
import {PviumHash} from "./lib/PviumHash.sol";
import {PviumIdentity} from "./PviumIdentity.sol";

/// @title PviumVerifier
/// @notice IP2IDVerifier backed by the Pvium ZK circuit. Verifies an identity proof against the
///         registered Privy signing key (via PviumIdentity) and, when a constraint commitment is
///         given, that the registered attestation signer has signed that commitment.
/// @dev proof = abi.encode(bytes zkProof, bytes32[] publicInputs). The wallet returned is the
///      EVM address the circuit read out of the Privy-signed token (public input 1), cross-checked
///      here against the proof's walletHash with the same formula. A constraint is satisfied by
///      `constraintSigner`'s EIP-712 signature over `Constraint(bytes32 commitment)` in this
///      contract's domain (name "PviumVerifier", version "1", chain id, this address), so a
///      signature is valid on one chain and one verifier only. Everything here is immutable: a
///      new attester, key or circuit is a new deployment the vault factory registers alongside.
///      What a commitment means is up to the funder; for a screening attestation it should
///      commit to the payee as well as the policy (e.g. keccak256(policyHash, identityHash)),
///      otherwise one signature releases every deposit under that policy for every payee.
contract PviumVerifier is IP2IDVerifier {
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant CONSTRAINT_TYPEHASH = keccak256("Constraint(bytes32 commitment)");

    PviumIdentity public immutable pviumIdentity;
    bytes32 private immutable _cachedDomainSeparator;
    uint256 private immutable _cachedChainId;
    /// @notice Address whose signature satisfies a constraint commitment; address(0) = unsupported.
    address public immutable constraintSigner;

    error IdentityMismatch();
    error NoEvmWallet();
    error WalletHashMismatch();
    error ConstraintsUnsupported();
    error InvalidConstraintSigner();
    error MalformedSignature();

    constructor(PviumIdentity _pviumIdentity, address _constraintSigner) {
        pviumIdentity = _pviumIdentity;
        constraintSigner = _constraintSigner;
        _cachedChainId = block.chainid;
        _cachedDomainSeparator = _domainSeparator(block.chainid);
    }

    /// @notice EIP-712 domain separator; recomputed if the chain id changes (chain fork).
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return block.chainid == _cachedChainId ? _cachedDomainSeparator : _domainSeparator(block.chainid);
    }

    function _domainSeparator(uint256 chainId) private view returns (bytes32) {
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, keccak256("PviumVerifier"), keccak256("1"), chainId, address(this)));
    }

    /// @inheritdoc IP2IDVerifier
    function getIdentityWallet(
        bytes32 identityHash,
        bytes calldata proof,
        Constraint calldata constraint
    ) external view returns (address wallet, uint64 iat) {
        (bytes memory zkProof, bytes32[] memory publicInputs) = abi.decode(proof, (bytes, bytes32[]));

        // Reverts (InvalidProof / UnknownSigner / …) unless the proof is valid under the registered key.
        PviumIdentity.Attestation memory a = pviumIdentity.verifyAttestation(zkProof, publicInputs);
        if (a.identityHash != identityHash) revert IdentityMismatch();
        if (a.wallet == address(0)) revert NoEvmWallet();
        if (PviumHash.walletHash(a.wallet) != a.walletHash) revert WalletHashMismatch();

        if (constraint.commitment != bytes32(0)) {
            if (constraintSigner == address(0)) revert ConstraintsUnsupported();
            if (_recover(constraint.commitment, constraint.signature) != constraintSigner) revert InvalidConstraintSigner();
        }
        return (a.wallet, a.iat);
    }

    /// @inheritdoc IP2IDVerifier
    function supportsConstraints() external view returns (bool) {
        return constraintSigner != address(0);
    }

    /// @notice The EIP-712 digest `constraintSigner` signs for a commitment.
    function constraintDigest(bytes32 commitment) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), keccak256(abi.encode(CONSTRAINT_TYPEHASH, commitment))));
    }

    /// @notice Suggested commitment for a screening attestation: binds the policy to the payee.
    function screeningCommitment(bytes32 policyHash, bytes32 identityHash) public pure returns (bytes32) {
        return keccak256(abi.encode(policyHash, identityHash));
    }

    function _recover(bytes32 commitment, bytes calldata signature) private view returns (address) {
        if (signature.length != 65) revert MalformedSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }
        if (v < 27) v += 27;
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert MalformedSignature();
        address signer = ecrecover(constraintDigest(commitment), v, r, s);
        if (signer == address(0)) revert MalformedSignature();
        return signer;
    }
}
