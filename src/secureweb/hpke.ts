/**
 * SecureWeb — RFC 9180 HPKE Base Mode (X-Wing Draft-06 + HKDF-SHA256 + ChaCha20-Poly1305)
 *
 * Implements RFC 9180 Hybrid Public Key Encryption using X-Wing Draft-06 KEM,
 * HKDF-SHA256 KDF, and ChaCha20-Poly1305 AEAD.
 */

import { extract as hkdfExtract, expand as hkdfExpand } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { encapsulate, decapsulate } from './xwing';
import type { HybridSealed } from './codec';

export const GATEWAY_REQUEST_INFO = new TextEncoder().encode('secureweb/gateway-e2e/v1:request');
export const GATEWAY_RESPONSE_INFO = new TextEncoder().encode('secureweb/gateway-e2e/v1:response');

// HPKE Suite ID: "HPKE" (4B) || KEM (2B, 0x647a for X-Wing Draft-06) || KDF (2B, 0x0001) || AEAD (2B, 0x0003)
const HPKE_SUITE_ID = new Uint8Array([
    0x48, 0x50, 0x4b, 0x45, // "HPKE"
    0x64, 0x7a,             // KEM: X-Wing Draft-06 (0x647a)
    0x00, 0x01,             // KDF: HKDF-SHA256
    0x00, 0x03,             // AEAD: ChaCha20-Poly1305
]);

const HPKE_V1_LABEL = new TextEncoder().encode('HPKE-v1');

function uint16BE(n: number): Uint8Array {
    return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

/**
 * RFC 9180 LabeledExtract
 */
export function labeledExtract(
    salt: Uint8Array,
    labelStr: string,
    ikm: Uint8Array,
    suiteId: Uint8Array = HPKE_SUITE_ID
): Uint8Array {
    const label = new TextEncoder().encode(labelStr);
    const labeledIkm = concatBytes(HPKE_V1_LABEL, suiteId, label, ikm);
    return hkdfExtract(sha256, labeledIkm, salt);
}

/**
 * RFC 9180 LabeledExpand
 */
export function labeledExpand(
    prk: Uint8Array,
    labelStr: string,
    info: Uint8Array,
    length: number,
    suiteId: Uint8Array = HPKE_SUITE_ID
): Uint8Array {
    const label = new TextEncoder().encode(labelStr);
    const labeledInfo = concatBytes(uint16BE(length), HPKE_V1_LABEL, suiteId, label, info);
    return hkdfExpand(sha256, prk, labeledInfo, length);
}

export interface HpkeKeyContext {
    key: Uint8Array;      // 32 bytes AEAD key
    baseNonce: Uint8Array;// 12 bytes base nonce
}

/**
 * RFC 9180 KeyScheduleBase (Mode::Base = 0x00)
 */
export function keyScheduleBase(
    sharedSecret: Uint8Array,
    info: Uint8Array,
    suiteId: Uint8Array = HPKE_SUITE_ID
): HpkeKeyContext {
    const empty = new Uint8Array(0);
    const zeroSalt = new Uint8Array([0]);

    const pskIdHash = labeledExtract(zeroSalt, 'psk_id_hash', empty, suiteId);
    const infoHash = labeledExtract(zeroSalt, 'info_hash', info, suiteId);

    const keyScheduleContext = concatBytes(new Uint8Array([0x00]), pskIdHash, infoHash);
    const secret = labeledExtract(sharedSecret, 'secret', empty, suiteId);

    const key = labeledExpand(secret, 'key', keyScheduleContext, 32, suiteId);
    const baseNonce = labeledExpand(secret, 'base_nonce', keyScheduleContext, 12, suiteId);

    return { key, baseNonce };
}

/**
 * Seal plaintext using HPKE Base Mode with X-Wing KEM.
 *
 * @param recipientPk - 1216 bytes X-Wing public key
 * @param info - Context info string (e.g. GATEWAY_REQUEST_INFO)
 * @param aad - Additional authenticated data (default empty)
 * @param plaintext - Data to encrypt
 */
export function seal(
    recipientPk: Uint8Array,
    info: Uint8Array = GATEWAY_REQUEST_INFO,
    aad: Uint8Array = new Uint8Array(0),
    plaintext: Uint8Array = new Uint8Array(0)
): HybridSealed {
    // 1. KEM Encapsulation
    const { kemOutput, sharedSecret } = encapsulate(recipientPk);

    // 2. Key Schedule
    const { key, baseNonce } = keyScheduleBase(sharedSecret, info);

    // 3. AEAD Encrypt (ChaCha20-Poly1305 with baseNonce for sequence 0)
    const cipher = chacha20poly1305(key, baseNonce, aad);
    const ciphertext = cipher.encrypt(plaintext);

    return {
        suite: 0, // XWingDraft06
        kemOutput,
        ciphertext,
    };
}

/**
 * Open ciphertext using HPKE Base Mode with X-Wing KEM.
 *
 * @param kemOutput - 1120 bytes KEM output
 * @param ciphertext - Ciphertext including 16-byte Poly1305 tag
 * @param secretKey - X-Wing recipient secret key (32B seed)
 * @param info - Context info string (e.g. GATEWAY_RESPONSE_INFO)
 * @param aad - Additional authenticated data (default empty)
 */
export function open(
    kemOutput: Uint8Array,
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
    info: Uint8Array = GATEWAY_RESPONSE_INFO,
    aad: Uint8Array = new Uint8Array(0)
): Uint8Array {
    if (kemOutput.length === 0) {
        throw new Error('HPKE open: kemOutput cannot be empty');
    }

    // 1. KEM Decapsulation
    const sharedSecret = decapsulate(kemOutput, secretKey);

    // 2. Key Schedule
    const { key, baseNonce } = keyScheduleBase(sharedSecret, info);

    // 3. AEAD Decrypt
    const cipher = chacha20poly1305(key, baseNonce, aad);
    return cipher.decrypt(ciphertext);
}
