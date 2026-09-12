# sdks

Client libraries for Pvium identity proofs. Each SDK bundles the circuit's verification key and
knows the public-input layout, so consumers can verify proofs and decode claims without any
other artifact.

| Folder | Package | Status |
| --- | --- | --- |
| `node/` | `@pvium/zk-verifier` (npm) | verify + decode |
| `python/` | | planned |
| `go/` | | planned |

All SDKs must agree on: the public-input order in `circuit/src/main.nr`, the identity type ids in
`circuit/src/identity.nr`, the `p2id.identity.v1` hash prefix, and the low-s signature rule for
provers. When the circuit changes, every SDK re-syncs its vk and publishes a new version.
