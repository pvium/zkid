// Internal re-exports for the SDK's own tests. Not part of the public API.
export { IdentityType, identityHash } from './identity.js';
export { decodeClaim, toPublicInputFields } from './publicInputs.js';
export { parseP256PublicKeyPem } from './signer.js';
export { verifyProof, shutdown } from './verify.js';
