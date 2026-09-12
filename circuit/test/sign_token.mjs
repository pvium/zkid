// Sign a JSON payload as an ES256 JWT with a P-256 private key (PKCS8 PEM). No dependencies.
// Usage: node test/sign_token.mjs <payload.json> <private.pem>   -> prints the token
import { createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';

const [payloadPath, keyPath] = process.argv.slice(2);
if (!payloadPath || !keyPath) {
  console.error('usage: sign_token.mjs <payload.json> <private.pem>');
  process.exit(2);
}
const b64u = (b) => Buffer.from(b).toString('base64url');
const header = b64u(JSON.stringify({ alg: 'ES256', typ: 'JWT' }));
const payload = b64u(JSON.stringify(JSON.parse(readFileSync(payloadPath, 'utf8'))));
const input = `${header}.${payload}`;
const key = createPrivateKey(readFileSync(keyPath));
const sig = sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' });
process.stdout.write(`${input}.${b64u(sig)}`);
