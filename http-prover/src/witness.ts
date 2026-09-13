import { InputError } from './errors.js';
import { LIMITS, TYPES, type IdentityTypeName } from './identity.js';
import type { ParsedToken, SignerKey } from './token.js';

/** Circuit inputs in the form noir_js accepts. Byte arrays are number[]; scalars are strings. */
export type CircuitInputs = Record<string, number[] | string>;

export interface WitnessRequest {
  token: ParsedToken;
  signer: SignerKey;
  identityType: IdentityTypeName;
  identityValue: string;
  /** Optional linked wallet to bind (second slot). */
  wallet?: string;
  /** Optional public field bound into the proof (escrow claims); zero-address for attestations. */
  recipient?: string;
}

// ---- JSON structure helpers, mirroring circuit/scripts/gen_prover.py ---------------------------

/** in_string[i] is true when byte i lies inside a JSON string (escape-aware). */
export function stringMap(payload: Buffer): boolean[] {
  const out = new Array<boolean>(payload.length);
  let inside = false;
  let escaped = false;
  for (let i = 0; i < payload.length; i++) {
    out[i] = inside;
    const b = payload[i];
    if (escaped) escaped = false;
    else if (inside) {
      if (b === 0x5c) escaped = true;
      else if (b === 0x22) inside = false;
    } else if (b === 0x22) inside = true;
  }
  return out;
}

function isMemberBoundary(b: number): boolean {
  return b === 0x7b || b === 0x2c; // { or ,
}

/** First occurrence of `key` outside any string and at a member boundary. */
export function findTopLevel(payload: Buffer, inString: boolean[], key: Buffer): number {
  let pos = 0;
  for (;;) {
    const i = payload.indexOf(key, pos);
    if (i === -1) throw new InputError(`top-level ${JSON.stringify(key.toString())} not found in token payload`);
    if (!inString[i] && i > 0 && isMemberBoundary(payload[i - 1])) return i;
    pos = i + 1;
  }
}

/** Index of `key` in hay[start, end) where the preceding byte is `{` or `,`. */
export function findMember(hay: Buffer, key: Buffer, start: number, end: number): number {
  let i = hay.indexOf(key, start);
  while (i !== -1 && i + key.length <= end) {
    if (i > 0 && isMemberBoundary(hay[i - 1])) return i;
    i = hay.indexOf(key, i + 1);
  }
  throw new InputError(`could not find member ${JSON.stringify(key.toString())}`);
}

export interface AccountRef {
  acctStart: number;
  acctEnd: number;
  typeIdx: number;
  valueIdx: number;
}

const esc = (s: string) => `\\"${s}\\"`; // \"s\"

/** Offsets of the flat account object inside linked_accounts with the given escaped type and key/value. */
export function locateAccount(
  payload: Buffer,
  laValueStart: number,
  laEnd: number,
  typeName: string,
  key: string,
  value: string,
): AccountRef {
  const typePat = Buffer.from(`${esc('type')}:${esc(typeName)}`);
  const valuePat = Buffer.from(`${esc(key)}:${esc(value)}`);
  let pos = laValueStart;
  for (;;) {
    const acctStart = payload.indexOf(0x7b, pos);
    if (acctStart === -1 || acctStart >= laEnd) {
      throw new InputError(`no linked account with type=${typeName} and ${key}=${value}`);
    }
    const acctEnd = payload.indexOf(0x7d, acctStart);
    if (acctEnd === -1 || acctEnd >= laEnd) throw new InputError('unterminated account object');
    const obj = payload.subarray(acctStart, acctEnd + 1);
    if (obj.includes(typePat) && obj.includes(valuePat)) {
      return {
        acctStart,
        acctEnd,
        typeIdx: findMember(payload, typePat, acctStart, acctEnd),
        valueIdx: findMember(payload, valuePat, acctStart, acctEnd),
      };
    }
    pos = acctEnd + 1;
  }
}

// ---- witness assembly -----------------------------------------------------------------------

export interface BuiltWitness {
  inputs: CircuitInputs;
  /** Token issued-at, parsed from the payload (the circuit re-derives and exposes it). */
  iat: number;
}

export function buildWitness(req: WitnessRequest, lowSSignature: Buffer): BuiltWitness {
  const { token, signer } = req;
  const spec = TYPES[req.identityType];
  if (!spec) throw new InputError(`unknown identity type "${req.identityType}"`);
  const value = Buffer.from(req.identityValue, 'utf8');
  if (value.length < 1 || value.length > LIMITS.MAX_VALUE_LEN) throw new InputError('identity value length out of range');
  if (token.headerB64.length > LIMITS.MAX_HEADER_B64_LEN || token.payloadB64.length > LIMITS.MAX_B64_LEN) {
    throw new InputError(`token too large for the circuit (header ${token.headerB64.length}, payload ${token.payloadB64.length})`);
  }

  const payload = token.payload;
  const inString = stringMap(payload);
  const laKey = Buffer.from('"linked_accounts":"');
  const laIdx = findTopLevel(payload, inString, laKey);
  const laValueStart = laIdx + laKey.length;
  let laEnd = laValueStart;
  while (laEnd < payload.length && inString[laEnd]) laEnd++;

  const acct = locateAccount(payload, laValueStart, laEnd, req.identityType, spec.key, req.identityValue);

  let wallet: [number, number, number, number, number] = [0, 0, 0, 0, 0];
  if (req.wallet) {
    const w = Buffer.from(req.wallet, 'utf8');
    if (w.length < 1 || w.length > LIMITS.MAX_VALUE_LEN) throw new InputError('wallet length out of range');
    const ref = locateAccount(payload, laValueStart, laEnd, 'wallet', TYPES.wallet.key, req.wallet);
    wallet = [ref.acctStart, ref.acctEnd, ref.typeIdx, ref.valueIdx, w.length];
  }

  const iatIdx = findTopLevel(payload, inString, Buffer.from('"iat":'));
  const iat = Number(payload.subarray(iatIdx + 6, iatIdx + 16).toString());

  const signing = token.signingInput;
  const padded = Buffer.concat([signing, Buffer.alloc(LIMITS.MAX_SIGNING_LEN - signing.length)]);

  const inputs: CircuitInputs = {
    signing_input: [...padded],
    signing_input_len: String(signing.length),
    signature: [...lowSSignature],
    signer_x: [...signer.x],
    signer_y: [...signer.y],
    payload_b64_start: String(token.headerB64.length + 1),
    iat_idx: String(iatIdx),
    linked_accounts_idx: String(laIdx),
    acct_start: String(acct.acctStart),
    acct_end: String(acct.acctEnd),
    type_idx: String(acct.typeIdx),
    value_idx: String(acct.valueIdx),
    value_len: String(value.length),
    wallet_acct_start: String(wallet[0]),
    wallet_acct_end: String(wallet[1]),
    wallet_type_idx: String(wallet[2]),
    wallet_value_idx: String(wallet[3]),
    wallet_value_len: String(wallet[4]),
    identity_type: String(spec.id),
    recipient: req.recipient ?? '0x0000000000000000000000000000000000000001',
  };
  return { inputs, iat };
}

/** Render inputs exactly as circuit/scripts/gen_prover.py writes Prover.toml (used for parity tests). */
export function toProverToml(inputs: CircuitInputs): string {
  return (
    Object.entries(inputs)
      .map(([k, v]) => (Array.isArray(v) ? `${k} = [${v.join(', ')}]` : `${k} = "${v}"`))
      .join('\n') + '\n'
  );
}
