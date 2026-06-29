# multiformats-clj

[![CI](https://github.com/kotoba-lang/multiformats/actions/workflows/ci.yml/badge.svg)](https://github.com/kotoba-lang/multiformats/actions/workflows/ci.yml)

**base58 · base32 · varint · sha2-256 multihash · CIDv1 — portable `.cljc`, pure Clojure, no
native deps, babashka-friendly. Compute a file's CID without shelling out to
`ipfs`.**

In a kotoba/IPFS codebase the same encodings get reimplemented in every actor:
base58btc for `did:key`, base32 for the multibase `b` CID, the sha2-256
multihash, and `CIDv1`. And computing a blob's content address usually means
shelling out to `ipfs add --only-hash` — a runtime dependency on the ipfs CLI
just to hash some bytes. This is that logic once, with **no dependency beyond
`java.security.MessageDigest`**, and it's **byte-identical to
`ipfs add --cid-version=1 --raw-leaves`** for single-block (≤256 KiB) inputs.

## Install

deps.edn (git dep):

```clojure
io.github.com-junkawasaki/multiformats-clj {:git/sha "<sha>"}
```

## Use

```clojure
(require '[multiformats.core :as mf])

;; content addresses (== go-ipfs / kubo)
(mf/cidv1-raw (.getBytes "hello\n"))   ;=> "bafkreicysg23kiwv34eg2d7qweipxwosdo2py4ldv42nbauguluen5v6am"
(mf/cid-of-file "build/app.wasm")       ;=> "bafkrei…"   (no ipfs CLI; single block)
(mf/kotoba-cid "ibuki")                 ;=> "bafyrei…"   dag-cbor CID of the name (KotobaCid)

;; multibase / multihash primitives
(mf/base58btc some-bytes)  (mf/base58btc-decode "z6Mk…body")
(mf/base32 some-bytes)     (mf/base32-decode "kreih…")
(mf/multihash-sha256 bytes)            ;=> 0x12 0x20 ‖ sha256
(mf/varint 300)                        ;=> bytes 0xac 0x02
(mf/cid->bytes "bafkrei…")             ;=> 0x01 0x55 0x12 0x20 …
```

`cid-of-file` replaces `ipfs add -Q --cid-version=1 --raw-leaves <path>` in build
and publish scripts, dropping the ipfs binary from the toolchain. It is
**single-block only** (≤256 KiB, the ipfs default chunk) and throws on larger
input — a multi-block dag-pb tree is intentionally out of scope.

## Correctness

`bb test` (no network, no ipfs at test time):
- **CIDv1-raw vectors minted by real go-ipfs/kubo** (`ipfs add --raw-leaves`) for
  empty / `"hello\n"` / a fixed string — reproduced exactly.
- multihash framing (`0x12 0x20` + the canonical `e3b0c442…` sha256 of empty),
  varint boundaries, base58/base32 round-trips (incl. leading-zero `1`s), and CID
  decode round-trips.

```
$ bb test
Ran 7 tests containing 28 assertions.
0 failures, 0 errors.
```

## License

Apache-2.0.
