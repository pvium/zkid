import { loadCircuitVersion, type CircuitVersion, type ProverConfig } from './config.js';
import { InputError } from './errors.js';
import { PUBLIC_INPUT_COUNT, PUBLIC_INPUT_IAT, TYPES, type IdentityTypeName } from './identity.js';
import { Prover } from './prove.js';
import { authenticate, normalizeLowS, parseToken } from './token.js';
import { buildWitness } from './witness.js';

export interface AttestationRequest {
  identityType: IdentityTypeName;
  identityValue: string;
  jwt: string;
  /** Linked wallet to bind. Required for attestations; omit only for escrow-claim proofs. */
  wallet?: string;
  recipient?: string;
  /** Circuit version to prove for. Omit for the latest; this prover serves exactly one. */
  version?: number;
  /**
   * If set, the request is accepted with 202 and the attestation (or the error) is POSTed to this
   * URL when ready. Put a secret in the URL if you need to authenticate the delivery. Without it
   * the response is synchronous.
   */
  callbackUrl?: string;
}

/** What the resolution API stores and later returns; verifiable with @pvium/zk-verifier. */
export interface Attestation {
  proof: string; // base64
  publicInputs: string; // base64, 11 × 32 bytes
  wallet: string | null;
  identityType: IdentityTypeName;
  issuedAt: number;
  /** Which circuit build produced this proof; verifiers must use the matching vk / contract. */
  circuitVersion: number;
  vkHash: string;
  /** kid of the Privy key that signed the token, when the token carried one. */
  kid?: string;
}

export class AttestationService {
  private readonly prover: Prover;
  readonly version: CircuitVersion;

  constructor(private readonly cfg: ProverConfig) {
    this.version = loadCircuitVersion(cfg);
    this.prover = new Prover(cfg);
  }

  get stats() {
    return this.prover.stats;
  }

  close(): Promise<void> {
    return this.prover.close();
  }

  /** Structural validation only; throws InputError. Used to reject bad async requests up front. */
  validateRequest(req: AttestationRequest): void {
    validate(req);
    if (req.version !== undefined && req.version !== this.version.circuitVersion) {
      throw new InputError(`unsupported circuit version ${req.version}; this prover serves version ${this.version.circuitVersion}`);
    }
  }

  async generate(req: AttestationRequest): Promise<Attestation> {
    validate(req);
    if (req.version !== undefined && req.version !== this.version.circuitVersion) {
      throw new InputError(`unsupported circuit version ${req.version}; this prover serves version ${this.version.circuitVersion}`);
    }
    const token = parseToken(req.jwt);
    const signer = await authenticate(token, this.cfg.signer); // fails fast on bad tokens
    const { inputs, iat } = buildWitness(
      { token, signer, identityType: req.identityType, identityValue: req.identityValue, wallet: req.wallet, recipient: req.recipient },
      normalizeLowS(token.signature),
    );
    const { proof, publicInputs } = await this.prover.prove(inputs);
    if (publicInputs.length !== PUBLIC_INPUT_COUNT * 32) throw new Error(`unexpected public input size ${publicInputs.length}`);
    const iatOut = Number(BigInt('0x' + publicInputs.subarray(PUBLIC_INPUT_IAT * 32, (PUBLIC_INPUT_IAT + 1) * 32).toString('hex')));
    if (iatOut !== iat) throw new Error('circuit iat does not match token iat');
    return {
      proof: proof.toString('base64'),
      publicInputs: publicInputs.toString('base64'),
      wallet: req.wallet ?? null,
      identityType: req.identityType,
      issuedAt: iat,
      circuitVersion: this.version.circuitVersion,
      vkHash: this.version.vkSha256,
      kid: signer.kid,
    };
  }
}

function validate(req: AttestationRequest): void {
  if (typeof req !== 'object' || req === null) throw new InputError('body must be a JSON object');
  if (typeof req.identityType !== 'string' || !(req.identityType in TYPES)) {
    throw new InputError(`identityType must be one of: ${Object.keys(TYPES).join(', ')}`);
  }
  if (typeof req.identityValue !== 'string' || req.identityValue.length === 0) throw new InputError('identityValue is required');
  if (typeof req.jwt !== 'string' || req.jwt.length === 0) throw new InputError('jwt is required');
  if (req.wallet !== undefined && (typeof req.wallet !== 'string' || req.wallet.length === 0)) throw new InputError('wallet must be a non-empty string');
  if (req.recipient !== undefined && !/^0x[0-9a-fA-F]{1,64}$/.test(req.recipient)) throw new InputError('recipient must be a hex field');
  if (req.version !== undefined && (!Number.isInteger(req.version) || req.version < 1)) throw new InputError('version must be a positive integer');
  if (req.callbackUrl !== undefined && typeof req.callbackUrl !== 'string') throw new InputError('callbackUrl must be a string');
}
