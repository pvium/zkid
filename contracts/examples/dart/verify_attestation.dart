// Verify a Pvium attestation (the JSON the API returns) against the on-chain PviumIdentity
// contract with a single read-only eth_call. Dependency-light on purpose so it maps 1:1 onto a
// Flutter app: only `package:crypto` for sha256; JSON-RPC over dart:io.
//
//   dart run verify_attestation.dart <rpcUrl> <contractAddress> <attestation.json> <identityType> <identityValue>
//
// Only hashes reach the RPC node: the raw identity is never put in calldata.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

const hashPrefix = 'p2id.identity.v1';
const identityTypeIds = {
  'email': 0, 'phone': 1, 'google_oauth': 2, 'twitter_oauth': 3, 'discord_oauth': 4,
  'github_oauth': 5, 'linkedin_oauth': 6, 'apple_oauth': 7, 'telegram': 8, 'tiktok_oauth': 9,
  'instagram_oauth': 10, 'farcaster': 11, 'wallet': 12,
};
// keccak256("verifyIdentityHashes(bytes,bytes32[],uint8,bytes32,bytes32)")[0..4]
const selector = '53825cfc'; // verifyIdentityHashes(bytes,bytes32[],uint8,bytes32,bytes32)
// Custom error selectors (keccak256 of the signature), for readable failures.
const errorNames = {
  '09bde339': 'InvalidProof()',
  '72a1d8d7': 'UnknownSigner(bytes32,bytes32)',
  'cb9aa4be': 'WrongPublicInputCount(uint256)',
  '880538f0': 'IdentityTypeMismatch(uint8,uint8)',
  'b2f0dc1f': 'IdentityMismatch()',
  'ab38b507': 'NoWallet()',
  '31e7efa5': 'WalletMismatch()',
};

/// sha256(prefix || typeId || normalize(value)); lowercase except phone and non-0x wallets.
Uint8List identityHash(String type, String value) {
  final id = identityTypeIds[type];
  if (id == null) throw ArgumentError('unknown identity type $type');
  final lower = (type != 'phone' && type != 'wallet') || (type == 'wallet' && value.startsWith('0x'));
  final v = lower ? value.replaceAllMapped(RegExp('[A-Z]'), (m) => m[0]!.toLowerCase()) : value;
  final preimage = [...utf8.encode(hashPrefix), id, ...utf8.encode(v)];
  return Uint8List.fromList(sha256.convert(preimage).bytes);
}

String hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
Uint8List word(BigInt v) { final s = v.toRadixString(16).padLeft(64, '0'); return Uint8List.fromList(List.generate(32, (i) => int.parse(s.substring(i * 2, i * 2 + 2), radix: 16))); }
Uint8List pad32(List<int> b) => Uint8List.fromList([...b, ...List.filled((32 - b.length % 32) % 32, 0)]);

/// ABI-encode verifyIdentityHashes(bytes, bytes32[], uint8, bytes32, bytes32).
Uint8List encodeCall(Uint8List proof, List<Uint8List> publicInputs, int identityType, Uint8List idHash, Uint8List walletHash) {
  // head: 5 slots; dynamic args (proof, publicInputs) hold offsets into the tail.
  final head = <Uint8List>[];
  final tail = <int>[];
  final headSize = 5 * 32;
  // proof (bytes)
  head.add(word(BigInt.from(headSize + tail.length)));
  tail.addAll(word(BigInt.from(proof.length)));
  tail.addAll(pad32(proof));
  // publicInputs (bytes32[])
  head.add(word(BigInt.from(headSize + tail.length)));
  tail.addAll(word(BigInt.from(publicInputs.length)));
  for (final w in publicInputs) tail.addAll(w);
  head.add(word(BigInt.from(identityType)));
  head.add(idHash);
  head.add(walletHash);
  return Uint8List.fromList([...hexToBytes(selector), for (final h in head) ...h, ...tail]);
}

Uint8List hexToBytes(String h) { h = h.startsWith('0x') ? h.substring(2) : h; return Uint8List.fromList(List.generate(h.length ~/ 2, (i) => int.parse(h.substring(i * 2, i * 2 + 2), radix: 16))); }

Future<Map<String, dynamic>> rpc(Uri url, String method, List<dynamic> params) async {
  final client = HttpClient();
  try {
    final req = await client.postUrl(url);
    req.headers.contentType = ContentType.json;
    req.write(jsonEncode({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}));
    final res = await req.close();
    return jsonDecode(await res.transform(utf8.decoder).join()) as Map<String, dynamic>;
  } finally {
    client.close();
  }
}

Future<void> main(List<String> args) async {
  if (args.length != 5) {
    stderr.writeln('usage: verify_attestation.dart <rpcUrl> <contractAddress> <attestation.json> <identityType> <identityValue>');
    exit(2);
  }
  final rpcUrl = args[0], contract = args[1], path = args[2], identityType = args[3], identityValue = args[4];
  final att = jsonDecode(await File(path).readAsString()) as Map<String, dynamic>;

  // 1. attestation JSON -> call arguments
  final proof = base64Decode(att['proof'] as String);
  final pi = base64Decode(att['publicInputs'] as String);
  if (pi.length % 32 != 0) throw StateError('publicInputs must be 32-byte words');
  final words = [for (var i = 0; i < pi.length; i += 32) Uint8List.fromList(pi.sublist(i, i + 32))];
  final typeId = identityTypeIds[identityType]!;
  final data = encodeCall(proof, words, typeId, identityHash(identityType, identityValue), identityHash('wallet', att['wallet'] as String));

  // 2. eth_call
  final res = await rpc(Uri.parse(rpcUrl), 'eth_call', [{'to': contract, 'data': '0x${hex(data)}'}, 'latest']);
  if (res['error'] != null) {
    final err = res['error'] as Map<String, dynamic>;
    // Revert data placement differs by node: a hex string, or nested under data.data (Hardhat).
    var revert = '';
    final d = err['data'];
    if (d is String) revert = d;
    else if (d is Map && d['data'] is String) revert = d['data'] as String;
    revert = revert.replaceFirst('0x', '');
    final name = errorNames[revert.length >= 8 ? revert.substring(0, 8) : ''] ?? 'revert: ${err['message']}';
    stdout.writeln('INVALID: $name');
    exit(1);
  }
  final issuedAt = BigInt.parse((res['result'] as String).substring(2), radix: 16).toInt();
  stdout.writeln('VALID: ${att['wallet']} is linked to $identityType $identityValue; attested at $issuedAt (${DateTime.fromMillisecondsSinceEpoch(issuedAt * 1000, isUtc: true)})');
}
