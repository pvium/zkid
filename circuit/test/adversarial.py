"""Adversarial circuit tests: the real sample payload plus injected decoys, signed with a
throwaway test key (we cannot sign with Privy's), and prover offsets pointing at the decoys.
Every attack must fail to solve.

Run via test/adversarial.sh (needs nargo and node on PATH)."""
import base64, json, os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")
NODE = os.environ.get("NODE", "node")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def b64url_decode(s: bytes) -> bytes:
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def set_field(toml: str, key: str, value) -> str:
    return re.sub(rf'^{key} = .*$', f'{key} = "{value}"', toml, flags=re.M)


def execute(toml: str, name: str) -> str:
    path = os.path.join(ROOT, f"Prover{name}.toml")
    with open(path, "w") as f:
        f.write(toml)
    r = run(["nargo", "execute", "-p", f"Prover{name}", f"adv_{name}"], cwd=ROOT)
    os.remove(path)
    return r.stdout + r.stderr


def expect_fail(label, output, needles):
    """The attack must fail to solve, with one of the listed assertion messages."""
    if isinstance(needles, str):
        needles = [needles]
    if "successfully solved" in output:
        print(f"  FAIL {label}: circuit ACCEPTED the attack")
        sys.exit(1)
    hit = next((n for n in needles if n in output), None)
    if hit is None:
        print(f"  FAIL {label}: rejected, but not with an expected assertion {needles}")
        print(output[-800:])
        sys.exit(1)
    print(f"  ok   {label} (rejected: {hit})")


def main():
    # 1. Malicious payload: real accounts plus an injected custom_metadata decoy that mimics an
    #    email account (single-escaped, exactly as Privy would serialise app-set metadata).
    with open(os.path.join(FIX, "sample_payload.json")) as f:
        payload = json.load(f)
    payload["custom_metadata"] = json.dumps(
        {"type": "email", "address": "victim@example.com", "iat": 1,
         "wallet": {"type": "wallet", "address": "0xAttacker000000000000000000000000000000000"}},
        separators=(",", ":"),
    )
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(payload, tf)
    r = run([NODE, os.path.join(HERE, "sign_token.mjs"), tf.name, os.path.join(FIX, "test_es256_private.pem")])
    os.remove(tf.name)
    if r.returncode != 0:
        print(r.stderr); sys.exit(1)
    token = r.stdout.strip()

    # 2. Honest witness for the real email in that same token.
    r = run([sys.executable, os.path.join(ROOT, "scripts/gen_prover.py"), "--jwt", token,
             "--pubkey", os.path.join(FIX, "test_es256_public.pem"),
             "--type", "email", "--value", "test-9988@privy.io",
             "--wallet", "0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98", "-o", os.path.join(ROOT, "ProverAdvBase.toml")])
    if r.returncode != 0:
        print(r.stderr); sys.exit(1)
    with open(os.path.join(ROOT, "ProverAdvBase.toml")) as f:
        base = f.read()
    os.remove(os.path.join(ROOT, "ProverAdvBase.toml"))

    decoded = b64url_decode(token.split(".")[1].encode())
    print("adversarial token: decoy custom_metadata present")
    out = execute(base, "Control")
    if "successfully solved" not in out:
        print("  FAIL control: honest witness for the real email did not solve"); print(out[-600:]); sys.exit(1)
    print("  ok   control: honest witness still proves")

    # 3. Attack A: point the account offsets at the decoy object inside custom_metadata.
    cm = decoded.find(b'"custom_metadata":"')
    d_start = decoded.find(b"{", cm)
    d_end = decoded.find(b"}", d_start)
    t_idx = decoded.find(b'\\"type\\":\\"email\\"', d_start, d_end)
    v_idx = decoded.find(b'\\"address\\":\\"', d_start, d_end)
    assert -1 not in (cm, d_start, d_end, t_idx, v_idx)
    victim = b"victim@example.com"
    attack = base
    for k, v in (("acct_start", d_start), ("acct_end", d_end), ("type_idx", t_idx), ("value_idx", v_idx), ("value_len", len(victim))):
        attack = set_field(attack, k, v)
    expect_fail("attack A: decoy account object in custom_metadata", execute(attack, "A"),
                "account object is not inside linked_accounts")

    # 4. Attack B: point iat_idx at the decoy iat inside the custom_metadata string.
    e_idx = decoded.find(b'"iat\\":', d_start, d_end)  # the escaped-quote form inside the string
    assert e_idx != -1
    attack = set_field(base, "iat_idx", e_idx)
    expect_fail("attack B: iat key inside a string claim", execute(attack, "B"), "iat must not be inside a string")

    # 5. Attack C: claim linked_accounts is somewhere inside a string (fake anchor).
    fake = decoded.find(b'"type\\":\\"email', d_start)  # any quote inside a string
    attack = set_field(base, "linked_accounts_idx", fake)
    expect_fail("attack C: linked_accounts anchor inside a string", execute(attack, "C"),
                "linked_accounts key must not be inside a string")

    # 6. Attack D: point the wallet slot at a decoy wallet object inside custom_metadata.
    w_start = decoded.find(b'{\\"type\\":\\"wallet\\"', d_start)
    w_end = decoded.find(b"}", w_start)
    wt_idx = decoded.find(b'\\"type\\":\\"wallet\\"', w_start, w_end)
    wv_idx = decoded.find(b'\\"address\\":\\"', w_start, w_end)
    assert -1 not in (w_start, w_end, wt_idx, wv_idx)
    attack = base
    for k, v in (("wallet_acct_start", w_start), ("wallet_acct_end", w_end), ("wallet_type_idx", wt_idx),
                 ("wallet_value_idx", wv_idx), ("wallet_value_len", len("0xAttacker000000000000000000000000000000000"))):
        attack = set_field(attack, k, v)
    expect_fail("attack D: decoy wallet object in custom_metadata", execute(attack, "D"),
                "account object is not inside linked_accounts")

    # 7. Attack E: wallet slot pointing at the email account object (type mismatch).
    attack = base
    for k in ("acct_start", "acct_end", "type_idx", "value_idx", "value_len"):
        attack = set_field(attack, "wallet_" + k, re.search(rf'^{k} = "(\d+)"', base, re.M).group(1))
    expect_fail("attack E: wallet slot pointed at a non-wallet account", execute(attack, "E"), "account type mismatch")

    # 8. Attack F: partial wallet — claim a prefix of a real address (shorter value_len).
    full_len = int(re.search(r'^wallet_value_len = "(\d+)"', base, re.M).group(1))
    attack = set_field(base, "wallet_value_len", full_len - 4)
    expect_fail("attack F: wallet value truncated to a prefix", execute(attack, "F"), "identity value not terminated")

    # 9. Attack G: over-long wallet — run past the closing quote into the next member.
    attack = set_field(base, "wallet_value_len", full_len + 4)
    # Whichever check trips first is fine: the terminator check or the no-backslash-in-value check.
    expect_fail("attack G: wallet value runs past its closing quote", execute(attack, "G"),
                ["identity value not terminated", "identity value contains a backslash"])

    # 10. Attack H: identity value truncated (same trick on the identity slot).
    id_len = int(re.search(r'^value_len = "(\d+)"', base, re.M).group(1))
    attack = set_field(base, "value_len", id_len - 1)
    expect_fail("attack H: identity value truncated", execute(attack, "H"), "identity value not terminated")

    # 11. The witness generator must refuse wallets that are not linked, including substrings /
    #     prefixes of real ones and case variants of a case-sensitive (Solana) address.
    def generator_refuses(label, wallet):
        r = run([sys.executable, os.path.join(ROOT, "scripts/gen_prover.py"), "--jwt", token,
                 "--pubkey", os.path.join(FIX, "test_es256_public.pem"),
                 "--type", "email", "--value", "test-9988@privy.io", "--wallet", wallet,
                 "-o", os.path.join(ROOT, "ProverAdvGen.toml")])
        if r.returncode == 0:
            os.remove(os.path.join(ROOT, "ProverAdvGen.toml"))
            print(f"  FAIL {label}: generator built a witness for an unlinked wallet"); sys.exit(1)
        if "no linked account" not in r.stderr:
            print(f"  FAIL {label}: unexpected error: {r.stderr[-300:]}"); sys.exit(1)
        print(f"  ok   {label} (generator refused)")

    generator_refuses("unlinked wallet",                    "0x1111111111111111111111111111111111111111")
    generator_refuses("prefix of a linked wallet",          "0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f")
    generator_refuses("linked wallet with extra chars",     "0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98ab")
    generator_refuses("solana address in different case",   "EXnVUEeELHiYynvjoQ9YhgxfMSDJC6tJm7VkFQY2b8WJ")

    print("all adversarial checks passed")


if __name__ == "__main__":
    main()
