import type { P256PublicKey } from './publicInputs.js';

/**
 * Pvium environments. Each is a Privy app: attestations are made from tokens that app signed,
 * so the trust anchor per environment is that app's signing keys.
 *
 * `keys` are the P-256 keys pinned at release time (from `jwksUrl`), so verification works with
 * no network call. `jwksUrl` is the live source: if an attestation's signer is not among the
 * pinned keys, the JWKS is fetched once (cached) to cover a key Privy rotated in after this
 * release. Rotation *out* is deliberate: a pinned key stays trusted until an SDK release drops it.
 */
export interface PviumEnvironment {
  name: 'production' | 'sandbox';
  privyAppId: string;
  jwksUrl: string;
  keys: Array<P256PublicKey & { kid: string }>;
}

export const PVIUM_ENVIRONMENTS: Record<'production' | 'sandbox', PviumEnvironment> = {
  production: {
    name: 'production',
    privyAppId: 'cmjzq9okg01kwjm0cq4b0xs74',
    jwksUrl: 'https://auth.privy.io/api/v1/apps/cmjzq9okg01kwjm0cq4b0xs74/jwks.json',
    keys: [
      {
        kid: 'gtxaE3pGoA51jLX-_Oeo75Zif0R3k-tBo7NsQpAy4RI',
        x: 0x95b9d9d18fbed9f5c3b8aab466271793539be2cbc86a7090dd92f4df600850den,
        y: 0x3acff34d3319d44a03afdd818474d3551e2b37ee2ff029ceac1ee74924eeb813n,
      },
      {
        kid: 'w43bEjqKgP4wGge2dXiLR18B83IgjT4rAjjDcXXd7E0',
        x: 0xf638cd1c8ae040434c3325c1fdfb4d313496b9e4d266017266c803c4e474cadan,
        y: 0x93d01d1f671d945cd44a46142a5c35e9b06c27bdac8d65d77c6996112509d029n,
      },
    ],
  },
  sandbox: {
    name: 'sandbox',
    privyAppId: 'cmhc6t92u001tju0cxkxg34on',
    jwksUrl: 'https://auth.privy.io/api/v1/apps/cmhc6t92u001tju0cxkxg34on/jwks.json',
    keys: [
      {
        kid: 'Lp_q4NY6tg5jSdiD790AIm01JR7GIJ_xmDVZZ6MVAfM',
        x: 0x487140ed4fa91d71559b5e015286c9b76c270883f59a5ae9febac9b291584cd1n,
        y: 0xd4cf5625205d28cbe6c8108a695929208c08f3bdc7790ab7023abe17dcdefc04n,
      },
      {
        kid: '1NtmKuIrWxOltnhgo5yNIyuFFmi-cQDW1Ucqv2185Og',
        x: 0x84e87db1d90fb3ef5079e6fbe8a50e8f2aee7f8ad66c13b837cc93e016e2b9aan,
        y: 0x27a0949bf003bb64d5a622a05737d2547efa8980267daf35cc75276cb30c9de5n,
      },
    ],
  },
};

export type PviumEnvironmentName = keyof typeof PVIUM_ENVIRONMENTS;

/** Typed choice of trusted signer: a Pvium environment (keys pinned in the SDK). */
export enum AttestationSigner {
  Production = 'production',
  Sandbox = 'sandbox',
}
