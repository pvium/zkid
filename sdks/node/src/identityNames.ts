import { IdentityType } from './identity.js';

/** Privy `linked_accounts[].type` strings, as developers know them. */
export const IDENTITY_TYPE_BY_NAME = {
  email: IdentityType.Email,
  phone: IdentityType.Phone,
  google_oauth: IdentityType.Google,
  twitter_oauth: IdentityType.Twitter,
  discord_oauth: IdentityType.Discord,
  github_oauth: IdentityType.Github,
  linkedin_oauth: IdentityType.Linkedin,
  apple_oauth: IdentityType.Apple,
  telegram: IdentityType.Telegram,
  tiktok_oauth: IdentityType.Tiktok,
  instagram_oauth: IdentityType.Instagram,
  farcaster: IdentityType.Farcaster,
  wallet: IdentityType.Wallet,
} as const;

export type IdentityTypeName = keyof typeof IDENTITY_TYPE_BY_NAME;

export function resolveIdentityType(t: IdentityType | IdentityTypeName): IdentityType {
  if (typeof t === 'number') {
    if (!Object.values(IDENTITY_TYPE_BY_NAME).includes(t)) throw new Error(`unknown identity type id ${t}`);
    return t;
  }
  const id = IDENTITY_TYPE_BY_NAME[t];
  if (id === undefined) throw new Error(`unknown identity type "${t}"`);
  return id;
}
