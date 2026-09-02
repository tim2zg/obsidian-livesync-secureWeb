import { describe, it, expect, beforeEach } from 'vitest';
import {
    padBucketFor,
    calculatePadLen,
    padBody,
    unpadBody,
    serializeGatewayEnvelope,
    deserializeGatewayEnvelope,
    serializeHybridSealed,
    deserializeHybridSealed,
    serializeGatewayHttpResponse,
    deserializeGatewayHttpResponse,
    type GatewayEnvelope,
    type GatewayHttpResponse,
} from './codec';
import {
    generateKeypair,
    encapsulate,
    decapsulate,
    XWING_PUBLIC_KEY_SIZE,
    XWING_KEM_OUTPUT_SIZE,
    XWING_SHARED_SECRET_SIZE,
} from './xwing';
import { seal, open, GATEWAY_REQUEST_INFO, GATEWAY_RESPONSE_INFO } from './hpke';
import {
    isHostAllowed,
    isKeyRevoked,
    decodeKeyBytes,
    encodeBase64,
    sealGatewayEnvelope,
    createSecureWebFetch,
    clearPubkeyCache,
    SecureWebEnvelopeError,
} from './envelope';
import goldenFixture from './golden_fixture.json';

function hexToBytes(hex: string): Uint8Array {
    const clean = hex.trim();
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

describe('SecureWeb Native Envelope Codec & Padding', () => {
    it('calculates padding buckets according to GAS_PAD_BUCKETS specification', () => {
        expect(padBucketFor(0)).toBe(1024);
        expect(padBucketFor(500)).toBe(1024);
        expect(padBucketFor(1016)).toBe(1024);
        expect(padBucketFor(1017)).toBe(4096);
        expect(padBucketFor(4088)).toBe(4096);
        expect(padBucketFor(4089)).toBe(16384);
        expect(padBucketFor(16376)).toBe(16384);
        expect(padBucketFor(16377)).toBe(32768);
    });

    it('pads and unpads body accurately', () => {
        const raw = new TextEncoder().encode('{"action":"sync"}');
        const padLen = calculatePadLen(raw.length);
        const padded = padBody(raw, padLen);

        expect(padded.length).toBe(raw.length + padLen);
        expect(padded.length + 8).toBe(padBucketFor(raw.length));

        const recovered = unpadBody(padded, padLen);
        expect(new TextDecoder().decode(recovered)).toBe('{"action":"sync"}');
    });

    it('serializes and deserializes GatewayEnvelope through Bincode 1.3', () => {
        const nonce = new Uint8Array(12);
        crypto.getRandomValues(nonce);

        const env: GatewayEnvelope = {
            version: 1,
            senderDeviceId: 'obsidian-dev-123',
            targetHost: 'couchdb.local',
            method: 'POST',
            pathAndQuery: '/obsidian-livesync/_changes?feed=longpoll',
            headers: [
                ['content-type', 'application/json'],
                ['x-test-header', 'valid-value'],
            ],
            body: new TextEncoder().encode('{"seq":100}'),
            nonce,
            padLen: 1000,
        };

        const encoded = serializeGatewayEnvelope(env);
        const decoded = deserializeGatewayEnvelope(encoded);

        expect(decoded.version).toBe(env.version);
        expect(decoded.senderDeviceId).toBe(env.senderDeviceId);
        expect(decoded.targetHost).toBe(env.targetHost);
        expect(decoded.method).toBe(env.method);
        expect(decoded.pathAndQuery).toBe(env.pathAndQuery);
        expect(decoded.headers).toEqual(env.headers);
        expect(decoded.body).toEqual(env.body);
        expect(decoded.nonce).toEqual(env.nonce);
        expect(decoded.padLen).toBe(env.padLen);
    });

    it('serializes and deserializes GatewayHttpResponse through Bincode 1.3', () => {
        const resp: GatewayHttpResponse = {
            status: 200,
            headers: [
                ['content-type', 'application/json'],
                ['server', 'SecureWeb Gateway'],
            ],
            body: new TextEncoder().encode('{"ok":true}'),
            padLen: 1005,
        };

        const encoded = serializeGatewayHttpResponse(resp);
        const decoded = deserializeGatewayHttpResponse(encoded);

        expect(decoded.status).toBe(200);
        expect(decoded.headers).toEqual(resp.headers);
        expect(decoded.body).toEqual(resp.body);
        expect(decoded.padLen).toBe(1005);
    });
});

describe('SecureWeb X-Wing Draft-06 Composite KEM', () => {
    it('generates keypairs with correct component lengths', () => {
        const kp = generateKeypair();
        expect(kp.publicKey.length).toBe(XWING_PUBLIC_KEY_SIZE);
        expect(kp.secretKey.length).toBe(32);
    });

    it('encapsulates and decapsulates to match shared secrets', () => {
        const recipient = generateKeypair();
        const { kemOutput, sharedSecret: senderSS } = encapsulate(recipient.publicKey);

        expect(kemOutput.length).toBe(XWING_KEM_OUTPUT_SIZE);
        expect(senderSS.length).toBe(XWING_SHARED_SECRET_SIZE);

        const recipientSS = decapsulate(kemOutput, recipient.secretKey);
        expect(bytesToHex(recipientSS)).toBe(bytesToHex(senderSS));
    });
});

describe('SecureWeb RFC 9180 HPKE Base Mode', () => {
    it('seals and opens plaintext roundtrip', () => {
        const recipient = generateKeypair();
        const plaintext = new TextEncoder().encode('Post-Quantum SecureWeb Envelope Test');

        const sealed = seal(recipient.publicKey, GATEWAY_REQUEST_INFO, new Uint8Array(0), plaintext);
        expect(sealed.suite).toBe(0);
        expect(sealed.kemOutput.length).toBe(XWING_KEM_OUTPUT_SIZE);
        expect(sealed.ciphertext.length).toBe(plaintext.length + 16);

        const opened = open(sealed.kemOutput, sealed.ciphertext, recipient.secretKey, GATEWAY_REQUEST_INFO, new Uint8Array(0));
        expect(new TextDecoder().decode(opened)).toBe('Post-Quantum SecureWeb Envelope Test');
    });

    it('rejects tampered ciphertext with Poly1305 authentication failure', () => {
        const recipient = generateKeypair();
        const plaintext = new TextEncoder().encode('Confidential payload');

        const sealed = seal(recipient.publicKey, GATEWAY_REQUEST_INFO, new Uint8Array(0), plaintext);

        const tamperedCiphertext = new Uint8Array(sealed.ciphertext);
        tamperedCiphertext[tamperedCiphertext.length - 1] ^= 0xff;

        expect(() => {
            open(sealed.kemOutput, tamperedCiphertext, recipient.secretKey, GATEWAY_REQUEST_INFO, new Uint8Array(0));
        }).toThrow();
    });

    it('rejects open with mismatched info string', () => {
        const recipient = generateKeypair();
        const plaintext = new TextEncoder().encode('Test');

        const sealed = seal(recipient.publicKey, GATEWAY_REQUEST_INFO, new Uint8Array(0), plaintext);

        expect(() => {
            open(sealed.kemOutput, sealed.ciphertext, recipient.secretKey, GATEWAY_RESPONSE_INFO, new Uint8Array(0));
        }).toThrow();
    });
});

describe('SecureWeb Golden Fixtures Interoperability (Rust <-> TypeScript)', () => {
    it('successfully opens request envelope sealed by real Rust secure-core', () => {
        const gatewaySecretKey = hexToBytes(goldenFixture.gateway_secret_key_hex);
        const sealedBincode = hexToBytes(goldenFixture.sealed_bincode_hex);

        // 1. Deserialize wire bincode HybridSealed
        const sealed = deserializeHybridSealed(sealedBincode);
        expect(sealed.suite).toBe(0);
        expect(sealed.kemOutput.length).toBe(XWING_KEM_OUTPUT_SIZE);

        // 2. Open HPKE ciphertext with gateway secret key
        const openedPlaintext = open(sealed.kemOutput, sealed.ciphertext, gatewaySecretKey, GATEWAY_REQUEST_INFO, new Uint8Array(0));

        // 3. Deserialize inner GatewayEnvelope
        const env = deserializeGatewayEnvelope(openedPlaintext);
        expect(env.senderDeviceId).toBe(goldenFixture.sender_device_id);
        expect(env.targetHost).toBe(goldenFixture.target_host);
        expect(env.method).toBe(goldenFixture.method);
        expect(env.pathAndQuery).toBe(goldenFixture.path_and_query);
        expect(env.padLen).toBe(goldenFixture.pad_len);
        expect(bytesToHex(env.nonce)).toBe(goldenFixture.nonce_hex);

        // 4. Strip padding and assert raw body match
        const unpadded = unpadBody(env.body, env.padLen);
        expect(new TextDecoder().decode(unpadded)).toBe(goldenFixture.raw_body_utf8);
    });

    it('successfully opens response sealed by real Rust secure-core', () => {
        const replySecretKey = hexToBytes(goldenFixture.gateway_secret_key_hex);
        const responseSealedBincode = hexToBytes(goldenFixture.response_sealed_bincode_hex);

        const sealed = deserializeHybridSealed(responseSealedBincode);
        const openedPlaintext = open(sealed.kemOutput, sealed.ciphertext, replySecretKey, GATEWAY_RESPONSE_INFO, new Uint8Array(0));

        const resp = deserializeGatewayHttpResponse(openedPlaintext);
        expect(resp.status).toBe(goldenFixture.response_status);
        expect(resp.padLen).toBe(goldenFixture.response_pad_len);

        const unpadded = unpadBody(resp.body, resp.padLen);
        expect(new TextDecoder().decode(unpadded)).toBe(goldenFixture.response_body_utf8);
    });
});

describe('SecureWeb High-Level Envelope Client & Transport', () => {
    beforeEach(() => {
        clearPubkeyCache();
    });

    it('evaluates isHostAllowed with exact, subdomain, and wildcard patterns', () => {
        const allowed = ['couchdb.local', '*.secure.home', 'matrix.lan'];
        expect(isHostAllowed('couchdb.local', allowed)).toBe(true);
        expect(isHostAllowed('COUCHDB.LOCAL', allowed)).toBe(true);
        expect(isHostAllowed('sub.secure.home', allowed)).toBe(true);
        expect(isHostAllowed('matrix.lan', allowed)).toBe(true);
        expect(isHostAllowed('evil.com', allowed)).toBe(false);
        expect(isHostAllowed('other.local', allowed)).toBe(false);

        expect(isHostAllowed('anything.com', ['*'])).toBe(true);
    });

    it('evaluates isKeyRevoked case-insensitively', () => {
        const revoked = ['abc123revoked', 'DEF456REVOKED'];
        expect(isKeyRevoked('abc123revoked', revoked)).toBe(true);
        expect(isKeyRevoked('ABC123REVOKED', revoked)).toBe(true);
        expect(isKeyRevoked('def456revoked', revoked)).toBe(true);
        expect(isKeyRevoked('validkey789', revoked)).toBe(false);
    });

    it('encodes and decodes base64 and hex keys accurately', () => {
        const kp = generateKeypair();
        const b64 = encodeBase64(kp.publicKey);
        const decodedFromB64 = decodeKeyBytes(b64);
        expect(bytesToHex(decodedFromB64)).toBe(bytesToHex(kp.publicKey));

        const hex = bytesToHex(kp.publicKey);
        const decodedFromHex = decodeKeyBytes(hex);
        expect(bytesToHex(decodedFromHex)).toBe(bytesToHex(kp.publicKey));
    });

    it('seals a high-level GatewayEnvelope to valid wire bytes', async () => {
        const gatewayKp = generateKeypair();
        const rawBody = new TextEncoder().encode('{"docs":[{"_id":"doc1","val":"hello"}]}');

        const sealedWireBytes = await sealGatewayEnvelope(
            'PUT',
            '/obsidian-livesync/doc1',
            rawBody,
            [['content-type', 'application/json']],
            'couchdb.local',
            gatewayKp.publicKey,
            'obsidian-device-42'
        );

        // Verify that the wire format unpacks cleanly
        const sealed = deserializeHybridSealed(sealedWireBytes);
        expect(sealed.suite).toBe(0);
        expect(sealed.kemOutput.length).toBe(XWING_KEM_OUTPUT_SIZE);

        const openedPlaintext = open(sealed.kemOutput, sealed.ciphertext, gatewayKp.secretKey, GATEWAY_REQUEST_INFO);
        const env = deserializeGatewayEnvelope(openedPlaintext);

        expect(env.senderDeviceId).toBe('obsidian-device-42');
        expect(env.targetHost).toBe('couchdb.local');
        expect(env.method).toBe('PUT');
        expect(env.pathAndQuery).toBe('/obsidian-livesync/doc1');

        const unpadded = unpadBody(env.body, env.padLen);
        expect(new TextDecoder().decode(unpadded)).toBe('{"docs":[{"_id":"doc1","val":"hello"}]}');
    });

    it('createSecureWebFetch enforces zero-plaintext fallback when host is rejected', async () => {
        const gatewayKp = generateKeypair();

        // Mock global fetch to return gateway metadata allowing only "matrix.lan"
        const originalFetch = globalThis.fetch;
        globalThis.fetch = async (input: RequestInfo | URL) => {
            const url = input.toString();
            if (url.includes('/.well-known/gateway-pubkey')) {
                return new Response(
                    JSON.stringify({
                        pubkey: encodeBase64(gatewayKp.publicKey),
                        hosts: ['matrix.lan'],
                        revoked: [],
                    }),
                    { status: 200, headers: { 'content-type': 'application/json' } }
                );
            }
            throw new Error('Should not reach backend');
        };

        try {
            const secureFetch = createSecureWebFetch({
                gatewayUrl: 'https://gateway.secure.local',
                targetHost: 'couchdb.local', // Not in allowed hosts!
            });

            await expect(secureFetch('https://gateway.secure.local/obsidian-livesync/_changes')).rejects.toThrow(
                SecureWebEnvelopeError
            );
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it('createSecureWebFetch enforces zero-plaintext fallback when key is revoked', async () => {
        const gatewayKp = generateKeypair();
        const b64Pk = encodeBase64(gatewayKp.publicKey);

        const originalFetch = globalThis.fetch;
        globalThis.fetch = async (input: RequestInfo | URL) => {
            const url = input.toString();
            if (url.includes('/.well-known/gateway-pubkey')) {
                return new Response(
                    JSON.stringify({
                        pubkey: b64Pk,
                        hosts: ['couchdb.local'],
                        revoked: [b64Pk], // Revoked!
                    }),
                    { status: 200, headers: { 'content-type': 'application/json' } }
                );
            }
            throw new Error('Should not reach backend');
        };

        try {
            const secureFetch = createSecureWebFetch({
                gatewayUrl: 'https://gateway.secure.local',
                targetHost: 'couchdb.local',
            });

            await expect(secureFetch('https://gateway.secure.local/obsidian-livesync/_changes')).rejects.toThrow(
                SecureWebEnvelopeError
            );
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it('createSecureWebFetch performs full request-response E2EE roundtrip', async () => {
        const gatewayKp = generateKeypair();
        const b64Pk = encodeBase64(gatewayKp.publicKey);

        const originalFetch = globalThis.fetch;
        globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = input.toString();
            if (url.includes('/.well-known/gateway-pubkey')) {
                return new Response(
                    JSON.stringify({
                        pubkey: b64Pk,
                        hosts: ['couchdb.local'],
                        revoked: [],
                    }),
                    { status: 200, headers: { 'content-type': 'application/json' } }
                );
            }

            if (url.includes('/gateway/e2e-envelope')) {
                // Gateway unwrap simulation
                const bodyBytes = new Uint8Array(init?.body as ArrayBuffer);
                const sealedReq = deserializeHybridSealed(bodyBytes);
                const reqPlaintext = open(sealedReq.kemOutput, sealedReq.ciphertext, gatewayKp.secretKey, GATEWAY_REQUEST_INFO);
                const env = deserializeGatewayEnvelope(reqPlaintext);

                // Extract reply pubkey
                const replyPubkeyHeader = env.headers.find(([k]) => k === 'x-reply-pubkey');
                expect(replyPubkeyHeader).toBeDefined();
                const replyPubkey = decodeKeyBytes(replyPubkeyHeader![1]);

                // Produce simulated CouchDB JSON response
                const respPayload = new TextEncoder().encode('{"ok":true,"rev":"1-abc"}');
                const respPadLen = calculatePadLen(respPayload.length);
                const paddedRespBody = padBody(respPayload, respPadLen);

                const gatewayResp: GatewayHttpResponse = {
                    status: 200,
                    headers: [['content-type', 'application/json']],
                    body: paddedRespBody,
                    padLen: respPadLen,
                };

                const respPlaintext = serializeGatewayHttpResponse(gatewayResp);
                const sealedResp = seal(replyPubkey, GATEWAY_RESPONSE_INFO, new Uint8Array(0), respPlaintext);
                const sealedRespWire = serializeHybridSealed(sealedResp);

                return new Response(sealedRespWire as unknown as BodyInit, {
                    status: 200,
                    headers: { 'content-type': 'application/octet-stream' },
                });
            }

            throw new Error(`Unexpected request: ${url}`);
        };

        try {
            const secureFetch = createSecureWebFetch({
                gatewayUrl: 'https://gateway.secure.local',
                targetHost: 'couchdb.local',
                deviceId: 'test-device-client-1',
            });

            const res = await secureFetch('https://gateway.secure.local/obsidian-livesync/doc1', {
                method: 'GET',
            });

            expect(res.status).toBe(200);
            expect(res.headers.get('content-type')).toBe('application/json');

            const text = await res.text();
            expect(text).toBe('{"ok":true,"rev":"1-abc"}');
        } finally {
            globalThis.fetch = originalFetch;
        }
    });
});
