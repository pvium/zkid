#!/usr/bin/env python3
"""Build Prover.toml for the pvium_identity circuit.

Usage:
  gen_prover.py --jwt <token> --pubkey <signer.pem> --type email --value test-9988@privy.io [--wallet 0x..] [-o Prover.toml]
  gen_prover.py --jwt <token> --pubkey <signer.pem> --type github_oauth --value dephizee

The token must be a real ES256-signed JWT: the circuit verifies its signature against the
P-256 public key in the PEM, so an unsigned or foreign-signed token will fail to prove.
Prints the expected public outputs so `nargo execute` can be checked against them.
"""
import argparse, base64, hashlib, json, sys

# Must match src/main.nr
MAX_HEADER_B64_LEN = 128
MAX_B64_LEN = 8000
MAX_SIGNING_LEN = MAX_HEADER_B64_LEN + 1 + MAX_B64_LEN
MAX_VALUE_LEN = 128
HASH_PREFIX = b"p2id.identity.v1"

# Must match src/identity.nr: id -> (type string, value key, case_insensitive)
TYPES = {
    "email": (0, "address", True),
    "phone": (1, "number", False),
    "google_oauth": (2, "email", True),
    "twitter_oauth": (3, "username", True),
    "discord_oauth": (4, "username", True),
    "github_oauth": (5, "username", True),
    "linkedin_oauth": (6, "email", True),
    "apple_oauth": (7, "email", True),
    "telegram": (8, "username", True),
    "tiktok_oauth": (9, "username", True),
    "instagram_oauth": (10, "username", True),
    "farcaster": (11, "username", True),
    "wallet": (12, "address", False),
}


def b64url(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def b64url_decode(s: bytes) -> bytes:
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def string_map(payload: bytes):
    """in_string[i] is True when byte i lies inside a JSON string (escape-aware), mirroring
    the circuit's scan. Used to place lookups exactly where the circuit will accept them."""
    out = [False] * len(payload)
    inside = escaped = False
    for i, b in enumerate(payload):
        out[i] = inside
        if escaped:
            escaped = False
        elif inside:
            if b == 0x5C:
                escaped = True
            elif b == 0x22:
                inside = False
        elif b == 0x22:
            inside = True
    return out


def find_top_level(payload: bytes, in_string, key: bytes) -> int:
    """First occurrence of `key` that is outside any string and at a member boundary."""
    pos = 0
    while True:
        i = payload.find(key, pos)
        if i == -1:
            raise SystemExit(f"top-level {key!r} not found in payload")
        if not in_string[i] and i > 0 and payload[i - 1] in b"{,":
            return i
        pos = i + 1


def find_member(hay: bytes, key: bytes, start=0, end=None) -> int:
    """Index of `key` in hay[start:end] where the preceding byte is `{` or `,`."""
    end = len(hay) if end is None else end
    i = hay.find(key, start, end)
    while i != -1:
        if i > 0 and hay[i - 1] in b"{,":
            return i
        i = hay.find(key, i + 1, end)
    raise SystemExit(f"could not find member {key!r}")


def normalize_value(type_id: int, value: str, ci: bool) -> str:
    """ASCII-lowercase for case-insensitive types and for EVM (0x…) wallet addresses."""
    if ci or (type_id == TYPES["wallet"][0] and value.startswith("0x")):
        return value.lower()
    return value


def identity_hash(type_id: int, value: str, ci: bool) -> bytes:
    v = normalize_value(type_id, value, ci)
    return hashlib.sha256(HASH_PREFIX + bytes([type_id]) + v.encode()).digest()


def locate_account(payload: bytes, la_value_start: int, la_end: int, type_name: str, key: str, value: bytes):
    """Offsets of the flat account object inside linked_accounts whose escaped `type` and
    `<key>` members equal the given values. Returns (acct_start, acct_end, type_idx, value_idx)."""
    type_pat = b'\\"type\\":\\"' + type_name.encode() + b'\\"'
    value_pat = b'\\"' + key.encode() + b'\\":\\"' + value + b'\\"'
    pos = la_value_start
    while True:
        acct_start = payload.find(b"{", pos, la_end)
        if acct_start == -1:
            raise SystemExit(f"no linked account with type={type_name} and {key}={value.decode()}")
        acct_end = payload.find(b"}", acct_start, la_end)
        if acct_end == -1:
            raise SystemExit("unterminated account object")
        obj = payload[acct_start:acct_end + 1]
        if type_pat in obj and value_pat in obj:
            break
        pos = acct_end + 1
    return (acct_start, acct_end,
            find_member(payload, type_pat, acct_start, acct_end),
            find_member(payload, value_pat, acct_start, acct_end))


P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def normalize_low_s(sig: bytes) -> bytes:
    """ECDSA signatures are malleable: (r, s) and (r, n - s) are both valid. Barretenberg's
    in-circuit verifier only accepts the low-s form, and JWT signers (WebCrypto, Go, ...) do
    not normalise, so every prover must apply this before building the witness."""
    r, s_val = sig[:32], int.from_bytes(sig[32:], "big")
    if s_val > P256_N // 2:
        s_val = P256_N - s_val
    return r + s_val.to_bytes(32, "big")


def load_p256_pubkey(pem_path: str):
    """Return (x, y) from a SubjectPublicKeyInfo PEM. The DER ends with the 65-byte
    uncompressed point 0x04 || x || y, so no ASN.1 library is needed."""
    with open(pem_path) as f:
        body = "".join(l for l in f if not l.startswith("-----"))
    der = base64.b64decode(body)
    point = der[-65:]
    if point[0] != 4 or len(der) < 65:
        raise SystemExit("expected an uncompressed P-256 public key in SPKI PEM")
    return point[1:33], point[33:65]


def split_hash(h: bytes):
    return int.from_bytes(h[:16], "big"), int.from_bytes(h[16:], "big")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jwt", required=True, help="full Privy identity token (header.payload.signature)")
    ap.add_argument("--pubkey", required=True, help="PEM (SPKI) file with the signer's P-256 public key")
    ap.add_argument("--type", required=True, choices=TYPES.keys())
    ap.add_argument("--value", required=True)
    ap.add_argument("--wallet", help="optional: also prove this linked wallet address (second slot)")
    ap.add_argument("-o", "--out", default="Prover.toml")
    a = ap.parse_args()

    parts = a.jwt.encode().split(b".")
    if len(parts) != 3:
        raise SystemExit("token must have 3 segments")
    header_b64, payload_b64 = parts[0], parts[1]
    signature = b64url_decode(parts[2])
    if len(signature) != 64:
        raise SystemExit(f"ES256 signature must be 64 bytes (r||s), got {len(signature)}")
    signature = normalize_low_s(signature)
    signer_x, signer_y = load_p256_pubkey(a.pubkey)

    signing = header_b64 + b"." + payload_b64
    payload = b64url_decode(payload_b64)
    if len(header_b64) > MAX_HEADER_B64_LEN or len(payload_b64) > MAX_B64_LEN:
        raise SystemExit(f"token too large for circuit limits (header {len(header_b64)}, payload {len(payload_b64)})")

    type_id, key, ci = TYPES[a.type]
    value = a.value.encode()
    if not 1 <= len(value) <= MAX_VALUE_LEN:
        raise SystemExit("value length out of range")

    # Anchor: the top-level "linked_accounts":"..." string. The account object must be inside it.
    in_string = string_map(payload)
    la_key = b'"linked_accounts":"'
    la_idx = find_top_level(payload, in_string, la_key)
    la_value_start = la_idx + len(la_key)
    la_end = la_value_start
    while la_end < len(payload) and in_string[la_end]:
        la_end += 1  # first byte no longer inside the string = its closing quote

    # Locate the identity's account object, and optionally the wallet's, inside that string.
    acct_start, acct_end, type_idx, value_idx = locate_account(payload, la_value_start, la_end, a.type, key, value)
    wallet = (0, 0, 0, 0, 0)
    # Public `wallet` input: the EVM address as a field, which the circuit checks against the
    # 0x-hex value it reads from the token. Zero for base58 wallets or no wallet slot.
    wallet_field = 0
    if a.wallet:
        wid, wkey, _ = TYPES["wallet"]
        wv = a.wallet.encode()
        if not 1 <= len(wv) <= MAX_VALUE_LEN:
            raise SystemExit("wallet length out of range")
        wallet = locate_account(payload, la_value_start, la_end, "wallet", wkey, wv) + (len(wv),)
        if a.wallet.lower().startswith("0x"):
            if len(a.wallet) != 42:
                raise SystemExit("EVM wallet must be 0x + 40 hex chars")
            wallet_field = int(a.wallet, 16)

    iat_idx = find_top_level(payload, in_string, b'"iat":')
    iat = int(payload[iat_idx + 6:iat_idx + 16])

    padded = signing + b"\x00" * (MAX_SIGNING_LEN - len(signing))
    lines = [
        f"signing_input = [{', '.join(str(b) for b in padded)}]",
        f'signing_input_len = "{len(signing)}"',
        f"signature = [{', '.join(str(b) for b in signature)}]",
        f"signer_x = [{', '.join(str(b) for b in signer_x)}]",
        f"signer_y = [{', '.join(str(b) for b in signer_y)}]",
        f'payload_b64_start = "{len(header_b64) + 1}"',
        f'iat_idx = "{iat_idx}"',
        f'linked_accounts_idx = "{la_idx}"',
        f'acct_start = "{acct_start}"',
        f'acct_end = "{acct_end}"',
        f'type_idx = "{type_idx}"',
        f'value_idx = "{value_idx}"',
        f'value_len = "{len(value)}"',
        f'wallet_acct_start = "{wallet[0]}"',
        f'wallet_acct_end = "{wallet[1]}"',
        f'wallet_type_idx = "{wallet[2]}"',
        f'wallet_value_idx = "{wallet[3]}"',
        f'wallet_value_len = "{wallet[4]}"',
        f'identity_type = "{type_id}"',
        f'wallet = "{wallet_field:#x}"',
    ]
    with open(a.out, "w") as f:
        f.write("\n".join(lines) + "\n")

    jh, ih = hashlib.sha256(signing).digest(), identity_hash(type_id, a.value, ci)
    jhi, jlo = split_hash(jh)
    ihi, ilo = split_hash(ih)
    print(f"wrote {a.out}  (signing input {len(signing)} bytes, payload {len(payload)} bytes)")
    print("expected public outputs:")
    xhi, xlo = split_hash(signer_x)
    yhi, ylo = split_hash(signer_y)
    print(f"  (jwt_hash, private) = 0x{jh.hex()}")
    print(f"  signer_x          = 0x{signer_x.hex()}")
    print(f"  signer_x_hi/lo    = 0x{xhi:032x} / 0x{xlo:032x}")
    print(f"  signer_y          = 0x{signer_y.hex()}")
    print(f"  signer_y_hi/lo    = 0x{yhi:032x} / 0x{ylo:032x}")
    print(f"  iat               = {iat}")
    print(f"  identity_hash     = 0x{ih.hex()}")
    print(f"  identity_hash_hi/lo = 0x{ihi:032x} / 0x{ilo:032x}")
    wh = identity_hash(TYPES["wallet"][0], a.wallet, False) if a.wallet else bytes(32)
    whi, wlo = split_hash(wh)
    print(f"  wallet_hash       = 0x{wh.hex()}" + ("" if a.wallet else "  (no wallet slot)"))
    print(f"  wallet_hash_hi/lo = 0x{whi:032x} / 0x{wlo:032x}")


if __name__ == "__main__":
    main()
