//! Small byte-level helpers over fixed-size arrays with dynamic (witness) offsets.

pub global LBRACE: u8 = 123; // {
pub global RBRACE: u8 = 125; // }
pub global LBRACKET: u8 = 91; // [
pub global RBRACKET: u8 = 93; // ]
pub global COMMA: u8 = 44; // ,
pub global QUOTE: u8 = 34; // "
pub global BACKSLASH: u8 = 92; // \
pub global DOT: u8 = 46; // .

/// Read `arr[idx]` when `enabled`, else return 0 without touching an out-of-range index.
pub fn read_at<let N: u32>(arr: [u8; N], idx: u32, enabled: bool) -> u8 {
    let safe_idx = if enabled { idx } else { 0 };
    let b = arr[safe_idx];
    if enabled {
        b
    } else {
        0
    }
}

/// Assert that `arr[start..start+M] == pattern`.
pub fn assert_bytes_at<let N: u32, let M: u32>(arr: [u8; N], start: u32, pattern: [u8; M]) {
    for k in 0..M {
        assert(arr[start + k] == pattern[k], "pattern mismatch");
    }
}

/// Assert that `arr[start..start+len] == pattern[0..len]` for a runtime `len <= M`.
pub fn assert_bytes_at_var<let N: u32, let M: u32>(
    arr: [u8; N],
    start: u32,
    pattern: [u8; M],
    len: u32,
) {
    assert(len <= M);
    for k in 0..M {
        let enabled = k < len;
        let b = read_at(arr, start + k, enabled);
        if enabled {
            assert(b == pattern[k], "pattern mismatch");
        }
    }
}

/// `arr[start..start+M] == pattern`, as a bool; reads nothing when `enabled` is false.
pub fn bytes_at_eq<let N: u32, let M: u32>(
    arr: [u8; N],
    start: u32,
    pattern: [u8; M],
    enabled: bool,
) -> bool {
    let mut ok = true;
    for k in 0..M {
        ok &= read_at(arr, start + k, enabled) == pattern[k];
    }
    ok
}

/// `arr[start..start+len] == pattern[0..len]` for a runtime `len <= M`, as a bool.
pub fn bytes_at_var_eq<let N: u32, let M: u32>(
    arr: [u8; N],
    start: u32,
    pattern: [u8; M],
    len: u32,
    enabled: bool,
) -> bool {
    let mut ok = len <= M;
    for k in 0..M {
        let on = enabled & (k < len);
        ok &= !on | (read_at(arr, start + k, on) == pattern[k]);
    }
    ok
}

/// Bool form of `assert_is_member_start`; false when `key_idx == 0`. Never underflows.
pub fn is_member_start<let N: u32>(arr: [u8; N], key_idx: u32, enabled: bool) -> bool {
    let has_prev = key_idx >= 1;
    let prev = read_at(arr, key_idx - (has_prev as u32), enabled & has_prev);
    has_prev & ((prev == LBRACE) | (prev == COMMA))
}

/// The byte before a JSON key must be `{` or `,` for the key to be a real member
/// of the object rather than a substring of some string value.
pub fn assert_is_member_start<let N: u32>(arr: [u8; N], key_idx: u32) {
    assert(key_idx >= 1);
    let prev = arr[key_idx - 1];
    assert((prev == LBRACE) | (prev == COMMA), "key is not at an object member boundary");
}

/// Parse exactly `D` ASCII decimal digits starting at `start`.
pub fn parse_decimal<let N: u32, let D: u32>(arr: [u8; N], start: u32) -> u64 {
    let mut acc: u64 = 0;
    for k in 0..D {
        let b = arr[start + k];
        assert((b >= 48) & (b <= 57), "expected ASCII digit");
        acc = acc * 10 + (b - 48) as u64;
    }
    acc
}

/// Pack a 32-byte big-endian hash into two 128-bit field elements (hi, lo).
pub fn pack_hash(h: [u8; 32]) -> (Field, Field) {
    let mut hi: Field = 0;
    let mut lo: Field = 0;
    for i in 0..16 {
        hi = hi * 256 + h[i] as Field;
        lo = lo * 256 + h[16 + i] as Field;
    }
    (hi, lo)
}

pub fn to_lower(b: u8) -> u8 {
    if (b >= 65) & (b <= 90) {
        b + 32
    } else {
        b
    }
}

#[test]
fn parse_decimal_reads_ten_digits() {
    let s = "\"iat\":1788916490,".as_bytes();
    assert(parse_decimal::<_, 10>(s, 6) == 1788916490);
}

#[test(should_fail)]
fn parse_decimal_rejects_non_digit() {
    let s = "\"iat\":17889164x0,".as_bytes();
    let _ = parse_decimal::<_, 10>(s, 6);
}

#[test]
fn pack_hash_roundtrip() {
    let mut h = [0; 32];
    h[0] = 1;
    h[15] = 2;
    h[16] = 3;
    h[31] = 4;
    let (hi, lo) = pack_hash(h);
    assert(hi == 0x01000000000000000000000000000002);
    assert(lo == 0x03000000000000000000000000000004);
}

#[test]
fn to_lower_only_touches_ascii_upper() {
    assert(to_lower(65) == 97);
    assert(to_lower(90) == 122);
    assert(to_lower(97) == 97);
    assert(to_lower(48) == 48);
    assert(to_lower(64) == 64);
}
