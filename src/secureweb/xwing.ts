/**
 * SecureWeb — X-Wing Draft-06 Composite KEM (ML-KEM-768 + X25519)
 *
 * Implements draft-connolly-cfrg-xwing-kem-06 composite post-quantum KEM
 * using @noble/post-quantum/hybrid.js `ml_kem768_x25519`.
 */

import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';

export const XWING_PUBLIC_KEY_SIZE = 1216; // 1184 (ML-KEM-768) + 32 (X25519)
export const XWING_KEM_OUTPUT_SIZE = 1120; // 1088 (ML-KEM-768 ct) + 32 (ephemeral X25519 pk)
export const XWING_SHARED_SECRET_SIZE = 32;

export interface XWingKeyPair {
    publicKey: Uint8Array; // 1216 bytes: 1184B pkM || 32B pkX
    secretKey: Uint8Array; // 32 bytes seed
}

export interface XWingEncapResult {
    kemOutput: Uint8Array; // 1120 bytes: 1088B ctM || 32B epkX
    sharedSecret: Uint8Array; // 32 bytes
}

/**
 * Generate a fresh X-Wing keypair.
 *
 * @param seed - Optional 32-byte seed. If omitted, cryptographically secure randomness is generated.
 */
export function generateKeypair(seed?: Uint8Array): XWingKeyPair {
    const s = seed || crypto.getRandomValues(new Uint8Array(32));
    const kp = ml_kem768_x25519.keygen(s);
    return {
        publicKey: kp.publicKey,
        secretKey: kp.secretKey,
    };
}

/**
 * Encapsulate to an X-Wing recipient public key.
 *
 * @param recipientPk - 1216 bytes: 1184B ML-KEM-768 pk || 32B X25519 pk
 */
export function encapsulate(recipientPk: Uint8Array): XWingEncapResult {
    if (recipientPk.length !== XWING_PUBLIC_KEY_SIZE) {
        throw new Error(`Invalid X-Wing public key length: expected ${XWING_PUBLIC_KEY_SIZE}, got ${recipientPk.length}`);
    }

    const encap = ml_kem768_x25519.encapsulate(recipientPk);
    return {
        kemOutput: encap.cipherText,
        sharedSecret: encap.sharedSecret,
    };
}

/**
 * Decapsulate an X-Wing ciphertext using recipient secret key.
 *
 * @param kemOutput - 1120 bytes: 1088B ML-KEM-768 ct || 32B ephemeral X25519 pk (ctX)
 * @param secretKey - X-Wing secret key (32-byte seed)
 */
export function decapsulate(kemOutput: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (kemOutput.length !== XWING_KEM_OUTPUT_SIZE) {
        throw new Error(`Invalid X-Wing kemOutput length: expected ${XWING_KEM_OUTPUT_SIZE}, got ${kemOutput.length}`);
    }

    return ml_kem768_x25519.decapsulate(kemOutput, secretKey);
}
