//! Identity type registry.
//!
//! Maps the public `identity_type` id to the Privy `linked_accounts` entry shape:
//! which `"type"` string the entry must carry and which key holds the identity value.
//! The verifier contract only needs to know the numeric id; the pairing is enforced here.

pub global NUM_TYPES: u32 = 13;
pub global MAX_TYPE_LEN: u32 = 16;
pub global MAX_KEY_LEN: u32 = 8;

pub global EMAIL: u8 = 0;
pub global PHONE: u8 = 1;
pub global GOOGLE: u8 = 2;
pub global TWITTER: u8 = 3;
pub global DISCORD: u8 = 4;
pub global GITHUB: u8 = 5;
pub global LINKEDIN: u8 = 6;
pub global APPLE: u8 = 7;
pub global TELEGRAM: u8 = 8;
pub global TIKTOK: u8 = 9;
pub global INSTAGRAM: u8 = 10;
pub global FARCASTER: u8 = 11;
pub global WALLET: u8 = 12;

/// Right-pad a string literal with zero bytes into a fixed-size array.
fn pad<let N: u32, let M: u32>(s: str<N>) -> [u8; M] {
    std::static_assert(N <= M, "string longer than pad width");
    let bytes = s.as_bytes();
    let mut out = [0; M];
    for i in 0..N {
        out[i] = bytes[i];
    }
    out
}

/// Value of the `"type"` field for each identity id.
pub global TYPE_NAMES: [[u8; MAX_TYPE_LEN]; NUM_TYPES] = [
    pad("email"),
    pad("phone"),
    pad("google_oauth"),
    pad("twitter_oauth"),
    pad("discord_oauth"),
    pad("github_oauth"),
    pad("linkedin_oauth"),
    pad("apple_oauth"),
    pad("telegram"),
    pad("tiktok_oauth"),
    pad("instagram_oauth"),
    pad("farcaster"),
    pad("wallet"),
];

pub global TYPE_LENS: [u32; NUM_TYPES] = [5, 5, 12, 13, 13, 12, 14, 11, 8, 12, 15, 9, 6];

/// Key inside the linked-account object that holds the identity value.
pub global KEY_NAMES: [[u8; MAX_KEY_LEN]; NUM_TYPES] = [
    pad("address"), // email
    pad("number"), // phone
    pad("email"), // google_oauth
    pad("username"), // twitter_oauth
    pad("username"), // discord_oauth
    pad("username"), // github_oauth
    pad("email"), // linkedin_oauth
    pad("email"), // apple_oauth
    pad("username"), // telegram
    pad("username"), // tiktok_oauth
    pad("username"), // instagram_oauth
    pad("username"), // farcaster
    pad("address"), // wallet
];

pub global KEY_LENS: [u32; NUM_TYPES] = [7, 6, 5, 8, 8, 8, 5, 5, 8, 8, 8, 8, 7];

/// Whether the value is ASCII-lowercased before hashing.
/// Wallet addresses are left untouched: Solana base58 is case-sensitive.
pub global CASE_INSENSITIVE: [bool; NUM_TYPES] =
    [true, false, true, true, true, true, true, true, true, true, true, true, false];

pub struct IdentitySpec {
    pub type_name: [u8; MAX_TYPE_LEN],
    pub type_len: u32,
    pub key_name: [u8; MAX_KEY_LEN],
    pub key_len: u32,
    pub case_insensitive: bool,
}

pub fn spec(identity_type: u8) -> IdentitySpec {
    let i = identity_type as u32;
    assert(i < NUM_TYPES, "unknown identity type");
    IdentitySpec {
        type_name: TYPE_NAMES[i],
        type_len: TYPE_LENS[i],
        key_name: KEY_NAMES[i],
        key_len: KEY_LENS[i],
        case_insensitive: CASE_INSENSITIVE[i],
    }
}

#[test]
fn table_lengths_match_strings() {
    for i in 0..NUM_TYPES {
        let mut n = 0;
        for j in 0..MAX_TYPE_LEN {
            if TYPE_NAMES[i][j] != 0 {
                n += 1;
            }
        }
        assert(n == TYPE_LENS[i]);
        let mut k = 0;
        for j in 0..MAX_KEY_LEN {
            if KEY_NAMES[i][j] != 0 {
                k += 1;
            }
        }
        assert(k == KEY_LENS[i]);
    }
}
