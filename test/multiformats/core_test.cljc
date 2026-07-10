(ns multiformats.core-test
  "Correctness pinned to the canonical `ipfs add --cid-version=1 --raw-leaves`
   output (these vectors were minted by real go-ipfs/kubo) plus encode/decode
   round-trips. No network, no ipfs CLI at test time."
  (:require [clojure.string :as str]
            #?(:clj [clojure.test :refer [deftest is]]
               :cljs [cljs.test :refer [deftest is] :include-macros true])
            [multiformats.core :as mf]))

(defn- utf8-bytes [s]
  #?(:clj (.getBytes ^String s "UTF-8")
     :cljs (.encode (js/TextEncoder.) s)))

(defn- bytes-of [ints]
  #?(:clj (byte-array (map unchecked-byte ints))
     :cljs (js/Uint8Array. (clj->js ints))))

(defn- empty-bytes []
  #?(:clj (byte-array 0) :cljs (js/Uint8Array. 0)))

;; ── CIDv1-raw vs go-ipfs (`ipfs add -Q --cid-version=1 --raw-leaves`) ─────────
(deftest cidv1-raw-matches-ipfs
  (is (= "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
         (mf/cidv1-raw (empty-bytes))) "empty input")
  (is (= "bafkreicysg23kiwv34eg2d7qweipxwosdo2py4ldv42nbauguluen5v6am"
         (mf/cidv1-raw (utf8-bytes "hello\n"))))
  (is (= "bafkreifsjhh4xb4ct3q652hbcbayexs57mu46imyrjxua4r6ofgft3qmv4"
         (mf/cidv1-raw (utf8-bytes "multiformats-clj")))))

;; ── multihash framing ─────────────────────────────────────────────────────────
(deftest multihash-sha256-frames-0x12-0x20
  (let [mh (mf/multihash-sha256 (empty-bytes))]
    ;; `alength`, not `count` -- `count` has no ICounted impl for a raw
    ;; Uint8Array on :cljs (works fine for byte-array on :clj, and for
    ;; :cljs's own JS Array, just not TypedArray); `alength` works on both.
    (is (= 34 (alength mh)))
    (is (= 0x12 (bit-and (aget mh 0) 0xff)) "sha2-256 code")
    (is (= 0x20 (bit-and (aget mh 1) 0xff)) "32-byte length")
    ;; sha256("") is the well-known e3b0c442…
    (is (= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
           (mf/hexify (bytes-of (drop 2 (seq mh))))))))

;; ── varint ────────────────────────────────────────────────────────────────────
(deftest varint-unsigned
  (is (= [0x00] (map #(bit-and % 0xff) (mf/varint 0))))
  (is (= [0x55] (map #(bit-and % 0xff) (mf/varint 0x55))))       ; raw codec, single byte
  (is (= [0x71] (map #(bit-and % 0xff) (mf/varint 0x71))))       ; dag-cbor codec
  (is (= [0x80 0x01] (map #(bit-and % 0xff) (mf/varint 128))))   ; multi-byte boundary
  (is (= [0xac 0x02] (map #(bit-and % 0xff) (mf/varint 300)))))

;; ── base58btc round-trip + leading-zero preservation ──────────────────────────
;; `vec`, not `seq` -- comparing raw seqs over byte-array/Uint8Array isn't
;; reliably `=`-comparable on every platform; `vec` always is.
(deftest base58-roundtrip
  (doseq [s ["" "Satoshi" "the quick brown fox"]]
    (let [b (utf8-bytes s)]
      (is (= (vec b) (vec (mf/base58btc-decode (mf/base58btc b)))))))
  ;; leading zero bytes → leading '1's (33 → alphabet index 33 = 'a')
  (is (= "11a" (mf/base58btc (bytes-of [0 0 33]))))
  (is (= (vec (bytes-of [0 0 33]))
         (vec (mf/base58btc-decode "11a"))))
  (is (= [0] (vec (mf/base58btc-decode "1"))) "'1' decodes to a single zero byte"))

;; ── base32 round-trip ─────────────────────────────────────────────────────────
(deftest base32-roundtrip
  (doseq [s ["" "f" "fo" "foo" "foob" "multiformats"]]
    (let [b (utf8-bytes s)]
      (is (= (vec b) (vec (mf/base32-decode (mf/base32 b))))))))

;; ── hex round-trip + odd-length rejection ─────────────────────────────────────
(deftest hex-roundtrip
  (doseq [ints [[] [0] [0xab] [0 1 2 250 255]]]
    (let [b (bytes-of ints)]
      (is (= ints (map #(bit-and % 0xff) (mf/unhex (mf/hexify b))))))))

(deftest unhex-rejects-odd-length-hex-strings
  ;; An odd number of hex digits is never valid encoded byte data;
  ;; `(partition 2 s)` would otherwise silently drop the trailing nibble
  ;; instead of erroring -- must fail loudly, not quietly decode a
  ;; shorter-than-intended byte array.
  (is (thrown? #?(:clj Exception :cljs js/Error) (mf/unhex "1")))
  (is (thrown? #?(:clj Exception :cljs js/Error) (mf/unhex "abc"))))

(deftest base32-decode-rejects-invalid-characters
  ;; b32-idx returns nil for a character outside the base32 alphabet, and
  ;; (int nil) throws on :clj (fails closed) but silently returns 0 on
  ;; :cljs (confirmed via a real compiled build) -- an invalid character
  ;; used to silently decode as if it were 'a' (alphabet index 0) on
  ;; :cljs instead of raising. "1", "0", "8", "9", and uppercase letters
  ;; are all outside this lowercase-only, no-padding RFC 4648 alphabet.
  (doseq [bad ["1" "0" "8" "9" "A" "="]]
    (is (thrown? #?(:clj Exception :cljs js/Error) (mf/base32-decode bad))
        (str "must reject invalid base32 character: " bad))))

;; ── CID decode round-trips its bytes ──────────────────────────────────────────
(deftest cid-bytes-roundtrip
  (let [c (mf/cidv1-raw (utf8-bytes "round-trip"))]
    (is (= c (str "b" (mf/base32 (mf/cid->bytes c)))))
    ;; the decoded prefix is version=1, codec=raw(0x55), mh=sha2-256(0x12),len=32(0x20)
    (let [bs (mf/cid->bytes c)]
      (is (= [0x01 0x55 0x12 0x20] (map #(bit-and % 0xff) (take 4 (seq bs))))))))

;; ── dag-cbor / kotoba-cid produce a bafyrei… (dag-cbor) CID ────────────────────
(deftest kotoba-cid-is-dag-cbor
  (let [c (mf/kotoba-cid "ibuki")]
    (is (str/starts-with? c "bafyrei"))
    (is (= [0x01 0x71 0x12 0x20] (map #(bit-and % 0xff) (take 4 (seq (mf/cid->bytes c))))))))
