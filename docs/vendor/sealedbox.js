/* libsodium-compatible crypto_box_seal (sealed box) on top of tweetnacl, plus a small BLAKE2b.
 * Used to encrypt secrets for the GitHub Actions secrets API, which expects a sealed box
 * made with the repository's public key. Works in browsers (window.sealedBox) and Node.
 */
(function (root) {
  "use strict";
  var MASK = (1n << 64n) - 1n;
  var IV = [0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
            0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n];
  var SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]];

  function rotr(x, n) { return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK; }

  function compress(h, block, t, last) {
    var m = new Array(16), v = new Array(16), i;
    for (i = 0; i < 16; i++) {
      var w = 0n;
      for (var b = 7; b >= 0; b--) w = (w << 8n) | BigInt(block[i * 8 + b]);
      m[i] = w;
    }
    for (i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = IV[i]; }
    v[12] ^= BigInt(t) & MASK;
    v[13] ^= (BigInt(t) >> 64n) & MASK;
    if (last) v[14] ^= MASK;
    function G(a, b, c, d, x, y) {
      v[a] = (v[a] + v[b] + x) & MASK; v[d] = rotr(v[d] ^ v[a], 32);
      v[c] = (v[c] + v[d]) & MASK;     v[b] = rotr(v[b] ^ v[c], 24);
      v[a] = (v[a] + v[b] + y) & MASK; v[d] = rotr(v[d] ^ v[a], 16);
      v[c] = (v[c] + v[d]) & MASK;     v[b] = rotr(v[b] ^ v[c], 63);
    }
    for (var r = 0; r < 12; r++) {
      var s = SIGMA[r % 10];
      G(0, 4, 8, 12, m[s[0]], m[s[1]]); G(1, 5, 9, 13, m[s[2]], m[s[3]]);
      G(2, 6, 10, 14, m[s[4]], m[s[5]]); G(3, 7, 11, 15, m[s[6]], m[s[7]]);
      G(0, 5, 10, 15, m[s[8]], m[s[9]]); G(1, 6, 11, 12, m[s[10]], m[s[11]]);
      G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
  }

  function blake2b(input, outlen) {
    var h = IV.slice();
    h[0] ^= 0x01010000n ^ BigInt(outlen);
    var n = input.length, off = 0;
    while (n - off > 128) {
      compress(h, input.subarray(off, off + 128), off + 128, false);
      off += 128;
    }
    var last = new Uint8Array(128);
    last.set(input.subarray(off));
    compress(h, last, n, true);
    var out = new Uint8Array(outlen);
    for (var i = 0; i < outlen; i++) out[i] = Number((h[i >> 3] >> BigInt(8 * (i & 7))) & 0xffn);
    return out;
  }

  function seal(nacl, message, recipientPk) {
    var eph = nacl.box.keyPair();
    var nin = new Uint8Array(64);
    nin.set(eph.publicKey, 0);
    nin.set(recipientPk, 32);
    var nonce = blake2b(nin, 24);
    var boxed = nacl.box(message, nonce, recipientPk, eph.secretKey);
    var out = new Uint8Array(32 + boxed.length);
    out.set(eph.publicKey, 0);
    out.set(boxed, 32);
    return out;
  }

  var api = { blake2b: blake2b, seal: seal };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.sealedBox = api;
})(typeof self !== "undefined" ? self : this);
