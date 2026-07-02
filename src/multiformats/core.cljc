;; multiformats.core — base58 / base32 / varint / multihash / CIDv1 in pure Clojure.
;;
;; Across a kotoba/IPFS codebase the same handful of encodings get reimplemented in
;; every actor: base58btc for did:key, base32 for the multibase 'b' CID, the
;; sha2-256 multihash, and `CIDv1`. Worse, computing a file's CID usually means
;; shelling out to `ipfs add --only-hash` — a runtime dependency on the ipfs CLI
;; just to get a content address. This library is that logic once, byte-identical
;; to `ipfs add --cid-version=1 --raw-leaves` for single-block (≤256 KiB) inputs.
;;
;;   (require '[multiformats.core :as mf])
;;   (mf/cidv1-raw (.getBytes "hello\n"))       ;=> "bafkrei…"  == ipfs add --raw-leaves
;;   (mf/cid-of-file "path/to/blob.wasm")        ;=> "bafkrei…"  (single-block, :clj only)
;;   (mf/kotoba-cid "ibuki")                     ;=> "bafyrei…"  dag-cbor CID of the name
;;   (mf/base58btc some-bytes) (mf/base32 some-bytes)
;;   (mf/cid->bytes "bafkrei…")                  ;=> the 0x01 0x55 0x12 0x20 … bytes
;;
;; PORTABLE (.cljc, real on both platforms — this is the fix for the honesty note
;; every downstream repo in this ecosystem carried: "multiformats/dag-cbor are
;; today JVM-only despite living in .cljc-named files"). `sha256` is the SHA-256
;; part of `@noble/hashes` on :cljs (pure JS, sync, no native deps — the same
;; choice `kotoba-lang/mst` and app-aozora's `kotobase.cid.cljc` already made) and
;; `java.security.MessageDigest` on :clj. Everything else (varint, base32, CID
;; assembly) is either fully shared bit-arithmetic or a small per-platform byte
;; construction. Only `cid-of-file` stays :clj-only — that's genuine file I/O, not
;; a gap.
(ns multiformats.core
  (:require [clojure.string :as str])
  #?(:cljs (:require ["@noble/hashes/sha2.js" :as noble-sha2]))
  #?(:clj (:import (java.security MessageDigest)
                   (java.io ByteArrayOutputStream))))

;; ── base58btc — base-256 ↔ base-58 by integer division, no BigInteger, so it
;; runs in the browser too (did:key 'z' multibase). ──────────────────────────
(def ^:private b58-alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
(def ^:private b58-idx (into {} (map-indexed (fn [i c] [c i]) b58-alphabet)))

(defn- ->ints [data] (map #(bit-and (int %) 0xff) (seq data)))

(defn base58btc
  "Bytes (a byte-array, Uint8Array, or a seq of 0..255 ints) → base58btc
   (Bitcoin alphabet) String. Pure integer arithmetic — clj + cljs."
  [data]
  (let [in (->ints data)
        digits (reduce
                (fn [digits b]
                  (let [[digits carry]
                        (reduce (fn [[ds carry] d]
                                  (let [v (+ (* d 256) carry)]
                                    [(conj ds (rem v 58)) (quot v 58)]))
                                [[] b] digits)]
                    (loop [digits digits carry carry]
                      (if (pos? carry)
                        (recur (conj digits (rem carry 58)) (quot carry 58))
                        digits))))
                [] in)
        nzeros (count (take-while zero? in))]
    (str (apply str (repeat nzeros \1))
         (apply str (map #(nth b58-alphabet %) (rseq digits))))))

(defn base58btc-decode
  "base58btc String → raw bytes (a byte-array on :clj, a vector of ints on
   :cljs). Leading '1's decode to leading zero bytes. Pure integer
   arithmetic, portable."
  [s]
  (let [bytes (reduce
               (fn [bs c]
                 (let [[bs carry]
                       (reduce (fn [[acc carry] d]
                                 (let [v (+ (* d 58) carry)]
                                   [(conj acc (rem v 256)) (quot v 256)]))
                               [[] (b58-idx c)] bs)]
                   (loop [bs bs carry carry]
                     (if (pos? carry)
                       (recur (conj bs (rem carry 256)) (quot carry 256))
                       bs))))
               [] (seq s))
        nzeros (count (take-while #(= \1 %) s))
        out (concat (repeat nzeros 0) (rseq bytes))]
    #?(:clj (byte-array (map unchecked-byte out)) :cljs (vec out))))

;; ── hashing ──────────────────────────────────────────────────────────────────
(defn sha256
  "SHA-256 digest bytes. :clj — java.security.MessageDigest. :cljs —
   @noble/hashes/sha2 (pure JS, sync)."
  [b]
  #?(:clj (.digest (MessageDigest/getInstance "SHA-256") b)
     :cljs (.sha256 noble-sha2 b)))

;; ── unsigned varint (LEB128) ──────────────────────────────────────────────────
(defn varint [n]
  #?(:clj
     (let [out (ByteArrayOutputStream.)]
       (loop [v (long n)]
         (if (< v 0x80)
           (do (.write out (int v)) (.toByteArray out))
           (do (.write out (int (bit-or (bit-and v 0x7f) 0x80)))
               (recur (unsigned-bit-shift-right v 7))))))
     :cljs
     (loop [v n out []]
       (if (< v 0x80)
         (conj out v)
         (recur (unsigned-bit-shift-right v 7)
                (conj out (bit-or (bit-and v 0x7f) 0x80)))))))

;; ── base32 (RFC 4648 lower, no padding) — the multibase 'b' alphabet ──────────
;; Fully portable: `.charAt` exists on both java.lang.String and JS strings.
(def ^:private b32-alphabet "abcdefghijklmnopqrstuvwxyz234567")
(def ^:private b32-idx (into {} (map-indexed (fn [i c] [c i]) b32-alphabet)))

(defn base32 [b]
  (let [bits (mapcat (fn [byte] (let [v (bit-and (int byte) 0xff)]
                                  (map #(bit-and (bit-shift-right v %) 1) [7 6 5 4 3 2 1 0])))
                     (seq b))]
    (->> bits
         (partition 5 5 nil)
         (map (fn [chunk]
                (let [padded (concat chunk (repeat (- 5 (count chunk)) 0))]
                  (.charAt b32-alphabet (reduce (fn [a bit] (+ (* a 2) bit)) 0 padded)))))
         (apply str))))

(defn base32-decode [s]
  (let [out (loop [cs (seq s) buf 0 bits 0 acc []]
              (if (empty? cs)
                acc
                (let [buf (bit-or (bit-shift-left buf 5) (int (b32-idx (first cs))))
                      bits (+ bits 5)]
                  (if (>= bits 8)
                    (recur (rest cs) buf (- bits 8)
                           (conj acc (bit-and (unsigned-bit-shift-right buf (- bits 8)) 0xff)))
                    (recur (rest cs) buf bits acc)))))]
    #?(:clj (byte-array out) :cljs (vec out))))

;; ── multihash (sha2-256 = 0x12, length 0x20) ──────────────────────────────────
;; Returns an array-like on both platforms (byte-array / Uint8Array), NOT a
;; plain vector on :cljs -- `aget`/`alength` (as this namespace's own docs
;; imply are safe on any "bytes" this library hands back, and as
;; `boundary?`-style consumers downstream do) silently return nil/0 on a
;; ClojureScript PersistentVector instead of throwing, which is exactly the
;; kind of gap that stays invisible until it corrupts output.
(defn multihash-sha256 [b]
  (let [h (sha256 b)]
    #?(:clj (byte-array (concat [(unchecked-byte 0x12) (unchecked-byte 0x20)] (seq h)))
       :cljs (let [out (js/Uint8Array. (+ 2 (alength h)))]
               (aset out 0 0x12)
               (aset out 1 0x20)
               (.set out h 2)
               out))))

;; ── CIDv1 ─────────────────────────────────────────────────────────────────────
;; codec multicodecs: raw = 0x55, dag-pb = 0x70, dag-cbor = 0x71
(def codec-raw 0x55)
(def codec-dag-cbor 0x71)

(defn cidv1
  "CIDv1 string from a content codec + a multihash. base32 'b' multibase."
  [codec multihash]
  (let [body (concat (seq (varint 0x01)) (seq (varint codec)) (seq multihash))]
    (str "b" (base32 #?(:clj (byte-array body) :cljs (vec body))))))

(defn cidv1-raw
  "CIDv1 of raw bytes (codec 0x55). Byte-identical to
   `ipfs add --cid-version=1 --raw-leaves` for a single block (input ≤ 256 KiB)."
  [b]
  (cidv1 codec-raw (multihash-sha256 b)))

(defn cidv1-dag-cbor
  "CIDv1 with the dag-cbor codec (0x71) over sha2-256 of the given bytes."
  [b]
  (cidv1 codec-dag-cbor (multihash-sha256 b)))

(defn kotoba-cid
  "KotobaCid::from_bytes(name) — CIDv1 dag-cbor sha2-256 of the UTF-8 name string.
   Matches the kotoba node's graph/RID content addressing."
  [name]
  (cidv1-dag-cbor #?(:clj (.getBytes ^String name "UTF-8")
                     :cljs (.encode (js/TextEncoder.) name))))

(defn cid->bytes
  "Decode a base32 'b' multibase CIDv1 back to its (version,codec,multihash) bytes."
  [cid]
  (when-not (str/starts-with? cid "b")
    (throw (ex-info "expected base32 'b' multibase CID" {:cid cid})))
  (base32-decode (subs cid 1)))

;; ── file helper (single-block raw CID) — genuinely :clj-only: file I/O differs
;; by platform, this isn't a gap the way sha256/CID assembly were. ────────────
(def ^:private single-block-limit 262144) ; ipfs default chunker = 256 KiB

#?(:clj
   (defn cid-of-file
     "CIDv1-raw of a file's bytes — the pure-Clojure equivalent of
      `ipfs add -Q --cid-version=1 --raw-leaves <path>`, removing the ipfs-CLI
      dependency from build/publish scripts. SINGLE-BLOCK ONLY: throws if the
      file exceeds the 256 KiB ipfs chunk size (a multi-block dag-pb CID is
      out of scope)."
     [path]
     (let [b (java.nio.file.Files/readAllBytes (.toPath (java.io.File. (str path))))]
       (when (> (count b) single-block-limit)
         (throw (ex-info "cid-of-file is single-block only (≤256 KiB); larger inputs need a dag-pb tree"
                         {:size (count b) :limit single-block-limit})))
       (cidv1-raw b)))
   :cljs
   (defn cid-of-file [& _]
     (throw (ex-info "multiformats.core/cid-of-file is :clj-only (file I/O)" {}))))

;; ── hex (handy alongside the codecs) ──────────────────────────────────────────
(defn hexify [b]
  #?(:clj (apply str (map #(format "%02x" (bit-and (int %) 0xff)) b))
     :cljs (apply str (map (fn [x]
                             (let [h (.toString (bit-and x 0xff) 16)]
                               (if (= 1 (count h)) (str "0" h) h)))
                           (seq b)))))

(defn unhex [s]
  (let [s (str/replace s #"\s" "")
        pairs (partition 2 s)]
    #?(:clj (byte-array (map (fn [[a b]] (unchecked-byte (Integer/parseInt (str a b) 16))) pairs))
       :cljs (vec (map (fn [[a b]] (js/parseInt (str a b) 16)) pairs)))))
