;; multiformats.core — base58 / base32 / varint / multihash / CIDv1 in pure Clojure.
;;
;; Across a kotoba/IPFS codebase the same handful of encodings get reimplemented in
;; every actor: base58btc for did:key, base32 for the multibase 'b' CID, the
;; sha2-256 multihash, and `CIDv1`. Worse, computing a file's CID usually means
;; shelling out to `ipfs add --only-hash` — a runtime dependency on the ipfs CLI
;; just to get a content address. This library is that logic once, with no native
;; deps (only `java.security.MessageDigest`), babashka-friendly, and byte-identical
;; to `ipfs add --cid-version=1 --raw-leaves` for single-block (≤256 KiB) inputs.
;;
;;   (require '[multiformats.core :as mf])
;;   (mf/cidv1-raw (.getBytes "hello\n"))       ;=> "bafkrei…"  == ipfs add --raw-leaves
;;   (mf/cid-of-file "path/to/blob.wasm")        ;=> "bafkrei…"  (single-block)
;;   (mf/kotoba-cid "ibuki")                     ;=> "bafyrei…"  dag-cbor CID of the name
;;   (mf/base58btc some-bytes) (mf/base32 some-bytes)
;;   (mf/cid->bytes "bafkrei…")                  ;=> the 0x01 0x55 0x12 0x20 … bytes
(ns multiformats.core
  #?(:clj (:require [clojure.string :as str]))
  #?(:clj (:import (java.security MessageDigest)
                   (java.io ByteArrayOutputStream))))

;; The CID/byte machinery is :clj — like every actor cid.cljc in this ecosystem,
;; content addressing runs server/build-side (bb/JVM), not in the browser. The
;; :cljs branch (bottom of file) exposes the SAME public API as throwing stubs so
;; a .cljc consumer compiles cleanly under ClojureScript and fails loudly if it
;; ever tries to hash in the browser (matching the prior per-actor contract).
#?(:clj
(do

;; ── hashing ───────────────────────────────────────────────────────────────────
(defn sha256 ^bytes [^bytes b]
  (.digest (MessageDigest/getInstance "SHA-256") b))

;; ── unsigned varint (LEB128) ──────────────────────────────────────────────────
(defn varint ^bytes [n]
  (let [out (ByteArrayOutputStream.)]
    (loop [v (long n)]
      (if (< v 0x80)
        (do (.write out (int v)) (.toByteArray out))
        (do (.write out (int (bit-or (bit-and v 0x7f) 0x80)))
            (recur (unsigned-bit-shift-right v 7)))))))

;; ── base58btc ─────────────────────────────────────────────────────────────────
(def ^:private b58-alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
(def ^:private b58-idx (into {} (map-indexed (fn [i c] [c i]) b58-alphabet)))

(defn base58btc ^String [^bytes b]
  (let [n (BigInteger. 1 b) fifty8 (biginteger 58)]
    (loop [n n acc ""]
      (if (pos? (.signum n))
        (recur (.divide n fifty8) (str (.charAt b58-alphabet (.intValue (.mod n fifty8))) acc))
        (str (apply str (repeat (count (take-while zero? (seq b))) \1)) acc)))))

(defn base58btc-decode ^bytes [^String s]
  (let [n (reduce (fn [acc c] (.add (.multiply acc (biginteger 58)) (biginteger (int (b58-idx c)))))
                  BigInteger/ZERO (seq s))
        body (if (zero? (.signum n))
               (byte-array 0)                        ; value 0 carries no body; zeros come from leading '1's
               (let [ba (.toByteArray n)]            ; strip BigInteger sign byte
                 (if (and (> (count ba) 1) (zero? (aget ba 0))) (byte-array (rest (seq ba))) ba)))
        leading (count (take-while #(= \1 %) s))]
    (byte-array (concat (repeat leading (byte 0)) (seq body)))))

;; ── base32 (RFC 4648 lower, no padding) — the multibase 'b' alphabet ──────────
(def ^:private b32-alphabet "abcdefghijklmnopqrstuvwxyz234567")
(def ^:private b32-idx (into {} (map-indexed (fn [i c] [c i]) b32-alphabet)))

(defn base32 ^String [^bytes b]
  (let [bits (mapcat (fn [byte] (let [v (bit-and (int byte) 0xff)]
                                  (map #(bit-and (bit-shift-right v %) 1) [7 6 5 4 3 2 1 0])))
                     (seq b))]
    (->> bits
         (partition 5 5 nil)
         (map (fn [chunk]
                (let [padded (concat chunk (repeat (- 5 (count chunk)) 0))]
                  (.charAt b32-alphabet (reduce (fn [a bit] (+ (* a 2) bit)) 0 padded)))))
         (apply str))))

(defn base32-decode ^bytes [^String s]
  (let [out (ByteArrayOutputStream.)]
    (loop [cs (seq s) buf 0 bits 0]
      (if (empty? cs)
        (.toByteArray out)
        (let [buf (bit-or (bit-shift-left buf 5) (int (b32-idx (first cs))))
              bits (+ bits 5)]
          (if (>= bits 8)
            (do (.write out (bit-and (unsigned-bit-shift-right buf (- bits 8)) 0xff))
                (recur (rest cs) buf (- bits 8)))
            (recur (rest cs) buf bits)))))))

;; ── multihash (sha2-256 = 0x12, length 0x20) ──────────────────────────────────
(defn multihash-sha256 ^bytes [^bytes b]
  (byte-array (concat [(unchecked-byte 0x12) (unchecked-byte 0x20)] (seq (sha256 b)))))

;; ── CIDv1 ─────────────────────────────────────────────────────────────────────
;; codec multicodecs: raw = 0x55, dag-pb = 0x70, dag-cbor = 0x71
(def codec-raw 0x55)
(def codec-dag-cbor 0x71)

(defn cidv1
  "CIDv1 string from a content codec + a multihash. base32 'b' multibase."
  ^String [codec ^bytes multihash]
  (str "b" (base32 (byte-array (concat (seq (varint 0x01)) (seq (varint codec)) (seq multihash))))))

(defn cidv1-raw
  "CIDv1 of raw bytes (codec 0x55). Byte-identical to
   `ipfs add --cid-version=1 --raw-leaves` for a single block (input ≤ 256 KiB)."
  ^String [^bytes b]
  (cidv1 codec-raw (multihash-sha256 b)))

(defn cidv1-dag-cbor
  "CIDv1 with the dag-cbor codec (0x71) over sha2-256 of the given bytes."
  ^String [^bytes b]
  (cidv1 codec-dag-cbor (multihash-sha256 b)))

(defn kotoba-cid
  "KotobaCid::from_bytes(name) — CIDv1 dag-cbor sha2-256 of the UTF-8 name string.
   Matches the kotoba node's graph/RID content addressing."
  ^String [^String name]
  (cidv1-dag-cbor (.getBytes name "UTF-8")))

(defn cid->bytes
  "Decode a base32 'b' multibase CIDv1 back to its (version,codec,multihash) bytes."
  ^bytes [^String cid]
  (when-not (str/starts-with? cid "b")
    (throw (ex-info "expected base32 'b' multibase CID" {:cid cid})))
  (base32-decode (subs cid 1)))

;; ── file helper (single-block raw CID) ────────────────────────────────────────
(def ^:private single-block-limit 262144) ; ipfs default chunker = 256 KiB

(defn cid-of-file
  "CIDv1-raw of a file's bytes — the pure-Clojure equivalent of
   `ipfs add -Q --cid-version=1 --raw-leaves <path>`, removing the ipfs-CLI
   dependency from build/publish scripts. SINGLE-BLOCK ONLY: throws if the file
   exceeds the 256 KiB ipfs chunk size (a multi-block dag-pb CID is out of scope)."
  ^String [path]
  (let [b (java.nio.file.Files/readAllBytes (.toPath (java.io.File. (str path))))]
    (when (> (count b) single-block-limit)
      (throw (ex-info "cid-of-file is single-block only (≤256 KiB); larger inputs need a dag-pb tree"
                      {:size (count b) :limit single-block-limit})))
    (cidv1-raw b)))

;; ── hex (handy alongside the codecs) ──────────────────────────────────────────
(defn hexify ^String [^bytes b]
  (apply str (map #(format "%02x" (bit-and (int %) 0xff)) b)))

(defn unhex ^bytes [^String s]
  (let [s (str/replace s #"\s" "")]
    (byte-array (map (fn [[a b]] (unchecked-byte (Integer/parseInt (str a b) 16)))
                     (partition 2 s)))))

)) ;; end #?(:clj (do …))

;; ── ClojureScript: same public API, throwing (content addressing is :clj-only) ──
#?(:cljs
(do
  (def codec-raw 0x55)
  (def codec-dag-cbor 0x71)
  (defn- nope [n] (throw (ex-info (str "multiformats.core/" n " is :clj-only "
                                       "(content addressing runs build/server-side, not in cljs)") {})))
  (defn sha256 [& _] (nope "sha256"))
  (defn varint [& _] (nope "varint"))
  (defn base58btc [& _] (nope "base58btc"))
  (defn base58btc-decode [& _] (nope "base58btc-decode"))
  (defn base32 [& _] (nope "base32"))
  (defn base32-decode [& _] (nope "base32-decode"))
  (defn multihash-sha256 [& _] (nope "multihash-sha256"))
  (defn cidv1 [& _] (nope "cidv1"))
  (defn cidv1-raw [& _] (nope "cidv1-raw"))
  (defn cidv1-dag-cbor [& _] (nope "cidv1-dag-cbor"))
  (defn kotoba-cid [& _] (nope "kotoba-cid"))
  (defn cid->bytes [& _] (nope "cid->bytes"))
  (defn cid-of-file [& _] (nope "cid-of-file"))
  (defn hexify [& _] (nope "hexify"))
  (defn unhex [& _] (nope "unhex"))))
