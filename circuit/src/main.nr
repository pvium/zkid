//! Pvium identity circuit.
//!
//! Proves that a Privy identity token (ES256 JWT), signed by the P-256 key
//! `(signer_x, signer_y)`, contains a linked account of a given `identity_type`
//! whose value hashes to `identity_hash`, without revealing the token or the value.
//! The ES256 signature is verified in-circuit over the SHA-256 digest of the JWT
//! signing input (`base64url(header).base64url(payload)`). The signer's public key
//! is exposed raw (each coordinate as two 128-bit halves) so a verifier can compare
//! it against the key it trusts, with no hashing to replicate.
//!
//! A second, optional account slot proves a `wallet` entry from the same token, so one proof
//! can state "identity X and wallet W belong to the same Privy user". Leave
//! `wallet_value_len = 0` to skip it; `wallet_hash` is then zero.
//!
//! The public input `wallet` is the EVM address of that wallet account. It is not trusted: the
//! circuit decodes the `0x…` hex address it read out of the signed token and asserts it equals
//! `wallet`, so the address a verifier pays is exactly the one Privy linked. For a non-EVM
//! wallet (base58) or no wallet slot, `wallet` must be zero and only `wallet_hash` identifies it.
//!
//! Public inputs:  identity_type, wallet
//! Public outputs: signer_x (hi, lo), signer_y (hi, lo), iat, identity_hash (hi, lo),
//!                 wallet_hash (hi, lo)
//!
//! `identity_hash = sha256(HASH_PREFIX || identity_type as u8 || value)` where `value`
//! is the linked-account value, ASCII-lowercased for case-insensitive types and for EVM
//! (`0x…`) wallet addresses. `wallet_hash` uses the same formula with type `wallet`. The
//! prefix domain-separates this commitment from any other SHA-256 use of the same bytes.

mod bytes;
mod identity;

use base64::BASE64_URL_DECODER;
use bytes::{
    bytes_at_eq, bytes_at_var_eq, is_member_start,
    BACKSLASH, COMMA, DOT, LBRACE, QUOTE, RBRACE, assert_bytes_at, 
    assert_is_member_start, pack_hash, parse_decimal, read_at, to_lower,
};
use sha256::sha256_var;

// ---- Size limits ------------------------------------------------------------
// The sample identity token with 21 linked accounts is 5719 bytes of signing input
// (4261 bytes of JSON). Limits below leave ~40% headroom. Tune to taste: cost is
// roughly linear in MAX_B64_LEN.

/// base64url(header) length limit. `{"alg":"ES256","typ":"JWT"}` encodes to 36 chars.
global MAX_HEADER_B64_LEN: u32 = 128;
/// base64url(payload) length limit. Multiple of 40 so the decoder has no ragged final chunk.
global MAX_B64_LEN: u32 = 8000;
/// Decoded payload limit: 3/4 of MAX_B64_LEN.
global MAX_PAYLOAD_LEN: u32 = 6000;
/// header + "." + payload
global MAX_SIGNING_LEN: u32 = MAX_HEADER_B64_LEN + 1 + MAX_B64_LEN;
/// Longest identity value (email / handle / wallet address) we will hash.
global MAX_VALUE_LEN: u32 = 128;
/// Unix timestamps are 10 digits until the year 2286.
global TS_DIGITS: u32 = 10;
/// Domain-separation prefix for `identity_hash`. Bump the version if the preimage layout changes.
global HASH_PREFIX: [u8; 16] = "p2id.identity.v1".as_bytes();

// JSON fragments. Top-level claims use plain quotes; linked_accounts is a
// JSON-encoded string inside the payload, so its quotes are escaped (`\"`).
global IAT_KEY: [u8; 6] = "\"iat\":".as_bytes();
/// `"linked_accounts":"` — the top-level key whose string value holds the account array.
global LINKED_ACCOUNTS_KEY: [u8; 19] = "\"linked_accounts\":\"".as_bytes();
/// `\"type\":\"`
global TYPE_KEY_ESC: [u8; 11] = "\\\"type\\\":\\\"".as_bytes();
/// `\":\"` — separator between an escaped key and an escaped string value
global KEY_VALUE_SEP_ESC: [u8; 5] = "\\\":\\\"".as_bytes();

pub struct PublicOutputs {
    pub signer_x_hi: Field,
    pub signer_x_lo: Field,
    pub signer_y_hi: Field,
    pub signer_y_lo: Field,
    /// Token issued-at (unix seconds): when Privy attested the claim. Freshness is the verifier's policy.
    pub iat: u64,
    pub identity_hash_hi: Field,
    pub identity_hash_lo: Field,
    pub wallet_hash_hi: Field,
    pub wallet_hash_lo: Field,
}

/// Prover-supplied offsets locating one linked-account object and its type/value members.
struct AccountRef {
    acct_start: u32,
    acct_end: u32,
    type_idx: u32,
    value_idx: u32,
    value_len: u32,
}

fn main(
    // --- private witness -------------------------------------------------------
    // `base64url(header) || "." || base64url(payload)`, zero-padded.
    signing_input: [u8; MAX_SIGNING_LEN],
    signing_input_len: u32,
    // ES256 signature `r || s` from the token's third segment.
    signature: [u8; 64],
    // Signer's P-256 public key, uncompressed coordinates (Privy's app verification key).
    signer_x: [u8; 32],
    signer_y: [u8; 32],
    // Index of the first payload base64 character (one past the ".").
    payload_b64_start: u32,
    // Index in the decoded payload of the opening quote of the top-level `"iat":` claim.
    iat_idx: u32,
    // Index in the decoded payload of the opening quote of the top-level `"linked_accounts":"` key.
    linked_accounts_idx: u32,
    // Index in the decoded payload of the `{` and `}` bounding the linked-account object.
    acct_start: u32,
    acct_end: u32,
    // Index of the backslash opening `\"type\":\"...` inside that object.
    type_idx: u32,
    // Index of the backslash opening `\"<key>\":\"<value>\"` inside that object.
    value_idx: u32,
    // Byte length of the identity value.
    value_len: u32,
    // Optional second slot: a `wallet` account from the same token. All zero = unused.
    wallet_acct_start: u32,
    wallet_acct_end: u32,
    wallet_type_idx: u32,
    wallet_value_idx: u32,
    wallet_value_len: u32,
    // --- public inputs -----------------------------------------------------------
    // See `identity.nr` for ids.
    identity_type: pub u8,
    // EVM address of the wallet slot's account, as a 160-bit field; asserted against the
    // address decoded from the token. Zero when the slot is unused or the wallet is not `0x…`.
    wallet: pub Field,
) -> pub PublicOutputs {

    // ---- 1. Hash the signing input exactly as the JWT signer did --------------------
    assert(signing_input_len <= MAX_SIGNING_LEN, "signing input too long");
    let jwt_hash = sha256_var(signing_input, signing_input_len);
    assert(
        std::ecdsa_secp256r1::verify_signature(signer_x, signer_y, signature, jwt_hash),
        "invalid ES256 signature",
    );

    // ---- 2. Locate and decode the payload segment -----------------------------------
    assert(payload_b64_start >= 2, "header cannot be empty");
    assert(payload_b64_start <= MAX_HEADER_B64_LEN + 1, "header too long");
    assert(signing_input[payload_b64_start - 1] == DOT, "expected '.' before payload");
    let b64_len = signing_input_len - payload_b64_start; // asserts start <= len
    assert(b64_len <= MAX_B64_LEN, "payload too long");

    let mut b64: [u8; MAX_B64_LEN] = [0; MAX_B64_LEN];
    for i in 0..MAX_B64_LEN {
        b64[i] = read_at(signing_input, payload_b64_start + i, i < b64_len);
    }
    let payload_vec: BoundedVec<u8, MAX_PAYLOAD_LEN> =
        BASE64_URL_DECODER::decode_var(BoundedVec::from_parts(b64, b64_len));
    let payload = payload_vec.storage();
    let payload_len = payload_vec.len();

    // ---- 2b. String-boundary scan -----------------------------------------------------
    // One pass recording, for every byte, whether it lies inside a JSON string. Escapes are
    // tracked by parity so a `\\"` sequence is read correctly. Nested data in a Privy token
    // only ever appears inside strings (`linked_accounts`, `custom_metadata` are stringified
    // JSON), so this is enough to anchor the account object to the `linked_accounts` string
    // and to keep the timestamp keys out of any string.
    let mut in_string: [bool; MAX_PAYLOAD_LEN] = [false; MAX_PAYLOAD_LEN];
    let mut active = true; // i < payload_len, maintained with one equality test per byte
    let mut inside = false;
    let mut escaped = false;
    for i in 0..MAX_PAYLOAD_LEN {
        active = active & (i != payload_len);
        let b = payload[i];
        in_string[i] = inside;
        let toggle = active & !escaped & (b == QUOTE);
        escaped = active & inside & !escaped & (b == BACKSLASH);
        inside = inside ^ toggle;
    }
    assert(!inside, "payload ends inside a string");

    // ---- 3. Top-level claim: iat --------------------------------------------------------
    assert(!in_string[iat_idx], "iat must not be inside a string");
    let iat = read_timestamp_claim(payload, payload_len, iat_idx, IAT_KEY);

    // ---- 4. The linked-account object ---------------------------------------------
    // `linked_accounts` is a JSON string containing an array of flat objects. The prover
    // points at one object; we check it is a single flat object (no nested braces), so
    // the type and value we read cannot come from two different accounts.
    // The object must live inside the string value of the top-level `"linked_accounts"` key:
    // that key is at top level, and every byte from the start of its value through the end
    // of the object is inside one string (a string boundary in between would mean we left it).
    assert(!in_string[linked_accounts_idx], "linked_accounts key must not be inside a string");
    assert_is_member_start(payload, linked_accounts_idx);
    assert_bytes_at(payload, linked_accounts_idx, LINKED_ACCOUNTS_KEY);
    let la_value_start = linked_accounts_idx + LINKED_ACCOUNTS_KEY.len();

    let identity_hash = prove_account(
        payload,
        payload_len,
        in_string,
        la_value_start,
        AccountRef { acct_start, acct_end, type_idx, value_idx, value_len },
        identity_type,
        true,
    )
        .hash;
    let has_wallet = wallet_value_len != 0;
    let wallet_acct = prove_account(
        payload,
        payload_len,
        in_string,
        la_value_start,
        AccountRef {
            acct_start: wallet_acct_start,
            acct_end: wallet_acct_end,
            type_idx: wallet_type_idx,
            value_idx: wallet_value_idx,
            value_len: wallet_value_len,
        },
        identity::WALLET,
        has_wallet,
    );
    let wallet_hash = wallet_acct.hash;

    // ---- 5. Bind the public `wallet` address to the wallet account read from the token -----
    // For an EVM wallet the value is "0x" + 40 hex chars (already lowercased); decode it and
    // require equality. Otherwise `wallet` must be zero. The verifier can therefore pay
    // `wallet` directly, and cross-check it against `wallet_hash` with the same formula.
    let is_evm = has_wallet & wallet_acct.evm_hex;
    assert(!is_evm | (wallet_acct.value_len == EVM_ADDRESS_LEN), "EVM wallet must be 0x + 40 hex chars");
    let mut decoded: Field = 0;
    for k in 0..40 {
        decoded = decoded * 16 + hex_digit(wallet_acct.value[2 + k], is_evm);
    }
    let expected_wallet = if is_evm { decoded } else { 0 };
    assert(wallet == expected_wallet, "wallet does not match the wallet account in the token");

    let (signer_x_hi, signer_x_lo) = pack_hash(signer_x);
    let (signer_y_hi, signer_y_lo) = pack_hash(signer_y);
    let (identity_hash_hi, identity_hash_lo) = pack_hash(identity_hash);
    let (wallet_hash_hi, wallet_hash_lo) = pack_hash(wallet_hash);
    PublicOutputs {
        signer_x_hi,
        signer_x_lo,
        signer_y_hi,
        signer_y_lo,
        iat,
        identity_hash_hi,
        identity_hash_lo,
        wallet_hash_hi,
        wallet_hash_lo,
    }
}

/// Length of an EVM address as Privy stores it: "0x" + 40 hex chars.
global EVM_ADDRESS_LEN: u32 = 42;

/// What `prove_account` established about one linked account.
struct ProvenAccount {
    /// sha256(HASH_PREFIX || identity_type || normalize(value)), or zero when disabled.
    hash: [u8; 32],
    /// normalize(value), zero-padded to MAX_VALUE_LEN.
    value: [u8; MAX_VALUE_LEN],
    value_len: u32,
    /// The value starts with "0x" (an EVM hex address).
    evm_hex: bool,
}

/// Check that `a` points at a flat account object of type `identity_type` inside the
/// `linked_accounts` string, and return `sha256(HASH_PREFIX || identity_type || normalize(value))`
/// together with the normalized value. With `enabled == false` every check is a no-op and the
/// result is all zeros; the effective offsets are forced to constants so no dynamic read can go
/// out of range.
fn prove_account<let N: u32>(
    payload: [u8; N],
    payload_len: u32,
    in_string: [bool; N],
    la_value_start: u32,
    a: AccountRef,
    identity_type: u8,
    enabled: bool,
) -> ProvenAccount {
    let off = !enabled;
    let acct_start = if enabled { a.acct_start } else { 0 };
    let acct_end = if enabled { a.acct_end } else { 0 };
    let type_idx = if enabled { a.type_idx } else { 0 };
    let value_idx = if enabled { a.value_idx } else { 0 };
    let value_len = if enabled { a.value_len } else { 0 };

    // A flat object (no nested braces) lying inside the linked_accounts string.
    assert(off | (acct_start >= la_value_start), "account object precedes linked_accounts");
    assert(off | (acct_start < acct_end), "bad account bounds");
    assert(off | (acct_end < payload_len), "account object out of range");
    assert(off | (payload[acct_start] == LBRACE), "account must start with '{'");
    assert(off | (payload[acct_end] == RBRACE), "account must end with '}'");
    // Range flags flipped by equality tests at the boundaries: in_obj covers
    // (acct_start, acct_end), in_la covers [la_value_start, acct_end].
    let mut in_obj = false;
    let mut in_la = false;
    for i in 0..N {
        let b = payload[i];
        in_la = in_la | (enabled & (i == la_value_start));
        let check_obj = in_obj & (i != acct_end);
        assert(!(check_obj & ((b == LBRACE) | (b == RBRACE))), "nested braces in account object");
        assert(!in_la | in_string[i], "account object is not inside linked_accounts");
        in_obj = check_obj | (enabled & (i == acct_start));
        in_la = in_la & (i != acct_end);
    }

    let spec = identity::spec(identity_type);

    // `{` or `,` then `\"type\":\"<type>\"`
    assert(off | (type_idx > acct_start), "type outside account object");
    assert(off | is_member_start(payload, type_idx, enabled), "type key is not at a member boundary");
    assert(off | bytes_at_eq(payload, type_idx, TYPE_KEY_ESC, enabled), "expected escaped type key");
    let type_val_start = type_idx + TYPE_KEY_ESC.len();
    assert(
        off | bytes_at_var_eq(payload, type_val_start, spec.type_name, spec.type_len, enabled),
        "account type mismatch",
    );
    let type_close = type_val_start + spec.type_len;
    assert(off | (read_at(payload, type_close, enabled) == BACKSLASH), "type value not terminated");
    assert(off | (read_at(payload, type_close + 1, enabled) == QUOTE), "type value not terminated");
    assert(off | (type_close + 1 < acct_end), "type outside account object");

    // `{` or `,` then `\"<key>\":\"<value>\"`
    assert(off | (value_idx > acct_start), "value outside account object");
    assert(off | is_member_start(payload, value_idx, enabled), "value key is not at a member boundary");
    assert(off | (read_at(payload, value_idx, enabled) == BACKSLASH), "expected escaped quote before key");
    assert(off | (read_at(payload, value_idx + 1, enabled) == QUOTE), "expected escaped quote before key");
    assert(
        off | bytes_at_var_eq(payload, value_idx + 2, spec.key_name, spec.key_len, enabled),
        "account key mismatch",
    );
    let sep_start = value_idx + 2 + spec.key_len;
    assert(off | bytes_at_eq(payload, sep_start, KEY_VALUE_SEP_ESC, enabled), "expected escaped separator");
    let value_start = sep_start + KEY_VALUE_SEP_ESC.len();

    assert(off | (value_len >= 1), "empty identity value");
    assert(value_len <= MAX_VALUE_LEN, "identity value too long");
    let value_close = value_start + value_len;
    assert(off | (read_at(payload, value_close, enabled) == BACKSLASH), "identity value not terminated");
    assert(off | (read_at(payload, value_close + 1, enabled) == QUOTE), "identity value not terminated");
    assert(off | (value_close + 1 < acct_end), "value outside account object");

    // sha256(HASH_PREFIX || identity_type || normalize(value))
    let prefix_len = HASH_PREFIX.len() + 1;
    let mut preimage: [u8; 16 + 1 + MAX_VALUE_LEN] = [0; 16 + 1 + MAX_VALUE_LEN];
    for k in 0..HASH_PREFIX.len() {
        preimage[k] = HASH_PREFIX[k];
    }
    preimage[HASH_PREFIX.len()] = identity_type;
    // EVM addresses are hex, so `0x…` wallet values are lowercased. Base58 (Solana) never
    // starts with '0', so this cannot misfire on a case-sensitive address.
    let two = enabled & (value_len >= 2);
    let evm_hex = (read_at(payload, value_start, two) == 48) & (read_at(payload, value_start + 1, two) == 120);
    let lower = spec.case_insensitive | (evm_hex & (identity_type == identity::WALLET));
    let mut value: [u8; MAX_VALUE_LEN] = [0; MAX_VALUE_LEN];
    for k in 0..MAX_VALUE_LEN {
        let on = enabled & (k < value_len);
        let b = read_at(payload, value_start + k, on);
        // A backslash would mean the "value" spans an escaped quote into the next member.
        assert(!(on & (b == BACKSLASH)), "identity value contains a backslash");
        let nb = if lower { to_lower(b) } else { b };
        preimage[prefix_len + k] = nb;
        value[k] = nb;
    }
    let h = sha256_var(preimage, prefix_len + value_len);
    ProvenAccount { hash: if enabled { h } else { [0; 32] }, value, value_len, evm_hex: enabled & evm_hex }
}

/// Value of a lowercase hex digit. When `on`, a byte that is not `0-9a-f` fails the proof;
/// when off, returns 0 without checking.
fn hex_digit(b: u8, on: bool) -> Field {
    let num = (b >= 48) & (b <= 57);
    let alpha = (b >= 97) & (b <= 102);
    assert(!on | num | alpha, "invalid hex digit in wallet address");
    let f = b as Field;
    if num {
        f - 48
    } else if alpha {
        f - 87
    } else {
        0
    }
}

/// Read a top-level numeric claim `"<key>":<10 digits>` followed by `,` or `}`.
fn read_timestamp_claim<let N: u32>(
    payload: [u8; N],
    payload_len: u32,
    key_idx: u32,
    key: [u8; 6],
) -> u64 {
    // key + digits + terminator must all be inside the decoded payload
    assert(key_idx + key.len() + TS_DIGITS < payload_len, "claim out of range");
    assert_is_member_start(payload, key_idx);
    assert_bytes_at(payload, key_idx, key);
    let digits_start = key_idx + key.len();
    let value = parse_decimal::<_, TS_DIGITS>(payload, digits_start);
    let term = payload[digits_start + TS_DIGITS];
    assert((term == COMMA) | (term == RBRACE), "timestamp has more than 10 digits");
    value
}
