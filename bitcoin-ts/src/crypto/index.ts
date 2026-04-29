/**
 * Bitcoin Core Crypto Module
 * 
 * @module crypto
 */

// SHA-256
export { CSHA256, sha256, sha256WebCrypto, hash256, SHA256D64 } from './sha256';

// RIPEMD-160
export { CRIPEMD160, ripemd160, hash160 } from './ripemd160';

// HMAC-SHA256
export { CHMAC_SHA256, hmacSha256, OUTPUT_SIZE as HMAC_SHA256_OUTPUT_SIZE } from './hmac_sha256';

// HMAC-SHA512
export { CHMAC_SHA512, hmacSha512, OUTPUT_SIZE as HMAC_SHA512_OUTPUT_SIZE } from './hmac_sha512';

// SHA-512
export { CSHA512, sha512, sha512_256 } from './sha512';

// ChaCha20
export { ChaCha20, ChaCha20Aligned, FSChaCha20 } from './chacha20';
export type { Nonce96 } from './chacha20';

// Poly1305
export { Poly1305, ChaCha20Poly1305 } from './poly1305';
