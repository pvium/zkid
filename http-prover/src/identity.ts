/** Privy linked-account types the circuit understands. Must match circuit/src/identity.nr. */
export const TYPES = {
  email: { id: 0, key: 'address' },
  phone: { id: 1, key: 'number' },
  google_oauth: { id: 2, key: 'email' },
  twitter_oauth: { id: 3, key: 'username' },
  discord_oauth: { id: 4, key: 'username' },
  github_oauth: { id: 5, key: 'username' },
  linkedin_oauth: { id: 6, key: 'email' },
  apple_oauth: { id: 7, key: 'email' },
  telegram: { id: 8, key: 'username' },
  tiktok_oauth: { id: 9, key: 'username' },
  instagram_oauth: { id: 10, key: 'username' },
  farcaster: { id: 11, key: 'username' },
  wallet: { id: 12, key: 'address' },
} as const;

export type IdentityTypeName = keyof typeof TYPES;

/** Circuit limits. Must match the globals in circuit/src/main.nr. */
export const LIMITS = {
  MAX_HEADER_B64_LEN: 128,
  MAX_B64_LEN: 8000,
  MAX_SIGNING_LEN: 128 + 1 + 8000,
  MAX_VALUE_LEN: 128,
} as const;

/** Index of `iat` among the 11 public inputs (see circuit/src/main.nr). */
export const PUBLIC_INPUT_IAT = 6;
export const PUBLIC_INPUT_COUNT = 11;
