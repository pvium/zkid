#!/bin/sh
# Copy the compiled circuit, its verification key and version.json from ../circuit into ./circuit.
# The full compiled JSON (13 MB, with source maps) stays local and gitignored; what gets committed
# is pvium_identity.json.gz: the same circuit stripped to the fields bb and noir_js need
# (noir_version, hash, abi, bytecode), ~4.6 MB. The service inflates it on startup if the plain
# file is missing, which is how the Railway/Docker image gets its circuit.
set -e
cd "$(dirname "$0")/.."
mkdir -p circuit
cp ../circuit/target/pvium_identity.json circuit/pvium_identity.json
cp ../circuit/target/proof_email/vk circuit/vk
cp ../circuit/version.json circuit/version.json
python3 - <<'PY'
import gzip, json
d = json.load(open('circuit/pvium_identity.json'))
slim = {k: d[k] for k in ('noir_version', 'hash', 'abi', 'bytecode')}
raw = json.dumps(slim, separators=(',', ':')).encode()
gz = gzip.compress(raw, 9)
with open('circuit/pvium_identity.json.gz', 'wb') as f:
    f.write(gz)
print(f"pvium_identity.json.gz: {len(raw) / 1048576:.1f} MB stripped -> {len(gz) / 1048576:.1f} MB gzipped")
PY
echo "synced circuit artifacts"
