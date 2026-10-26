import { describe, it, expect, beforeEach } from 'vitest';
import {
    padBucketFor,
    serializeHybridSealed,
    deserializeHybridSealed,
    padToBucketFrame,
    unpadFrame,
    serializeServiceRequest,
    deserializeServiceRequest,
    serializeRouteEnvelope,
    deserializeRouteEnvelope,
    serializeServiceResponse,
    deserializeServiceResponse,
    ROUTE_ENVELOPE_VERSION,
    SERVICE_ENVELOPE_VERSION,
} from './codec';
import {
    generateKeypair,
    encapsulate,
    decapsulate,
    XWING_PUBLIC_KEY_SIZE,
    XWING_KEM_OUTPUT_SIZE,
    XWING_SHARED_SECRET_SIZE,
} from './xwing';
import {
    seal,
    open,
    ROUTE_REQUEST_INFO,
    SERVICE_REQUEST_INFO,
    SERVICE_RESPONSE_INFO,
} from './hpke';
import {
    isHostAllowed,
    isKeyRevoked,
    decodeKeyBytes,
    encodeBase64,
    sealRouteEnvelopeV2,
    createSecureWebFetch,
    clearPubkeyCache,
    SecureWebEnvelopeError,
} from './envelope';

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

        const sealed = seal(recipient.publicKey, ROUTE_REQUEST_INFO, new Uint8Array(0), plaintext);
        expect(sealed.suite).toBe(0);
        expect(sealed.kemOutput.length).toBe(XWING_KEM_OUTPUT_SIZE);
        expect(sealed.ciphertext.length).toBe(plaintext.length + 16);

        const opened = open(sealed.kemOutput, sealed.ciphertext, recipient.secretKey, ROUTE_REQUEST_INFO, new Uint8Array(0));
        expect(new TextDecoder().decode(opened)).toBe('Post-Quantum SecureWeb Envelope Test');
    });

    it('rejects tampered ciphertext with Poly1305 authentication failure', () => {
        const recipient = generateKeypair();
        const plaintext = new TextEncoder().encode('Confidential payload');

        const sealed = seal(recipient.publicKey, ROUTE_REQUEST_INFO, new Uint8Array(0), plaintext);

        const tamperedCiphertext = new Uint8Array(sealed.ciphertext);
        tamperedCiphertext[tamperedCiphertext.length - 1] ^= 0xff;

        expect(() => {
            open(sealed.kemOutput, tamperedCiphertext, recipient.secretKey, ROUTE_REQUEST_INFO, new Uint8Array(0));
        }).toThrow();
    });

    it('rejects open with mismatched info string', () => {
        const recipient = generateKeypair();
        const plaintext = new TextEncoder().encode('Test');

        const sealed = seal(recipient.publicKey, ROUTE_REQUEST_INFO, new Uint8Array(0), plaintext);

        expect(() => {
            open(sealed.kemOutput, sealed.ciphertext, recipient.secretKey, SERVICE_RESPONSE_INFO, new Uint8Array(0));
        }).toThrow();
    });
});

describe('SecureWeb True-E2E v2 — two-layer opaque router format', () => {
    it('frames and unframes payloads into SWP1 buckets', () => {
        const payload = new TextEncoder().encode('x'.repeat(1000));
        const frame = padToBucketFrame(payload);
        expect(frame.length).toBe(1024);
        expect(bytesToHex(frame.subarray(0, 4))).toBe('53575031'); // "SWP1"
        expect(new TextDecoder().decode(unpadFrame(frame))).toBe('x'.repeat(1000));

        const big = new Uint8Array(20000).fill(7);
        const bigFrame = padToBucketFrame(big);
        expect(bigFrame.length).toBe(32768);
        expect(unpadFrame(bigFrame)).toEqual(big);

        const corrupt = new Uint8Array(frame);
        corrupt[0] = 0x00;
        expect(() => unpadFrame(corrupt)).toThrow(/SWP1/);
    });

    it('round-trips ServiceRequest / RouteEnvelope / ServiceResponse through bincode', () => {
        const req = {
            version: SERVICE_ENVELOPE_VERSION,
            method: 'POST',
            pathAndQuery: '/obsidian-vault/_bulk_docs?x=1',
            headers: [['content-type', 'application/json']] as [string, string][],
            body: new TextEncoder().encode('{"docs":[]}'),
            auth: 'swt_token',
        };
        expect(deserializeServiceRequest(serializeServiceRequest(req))).toEqual(req);

        const noAuth = { ...req, auth: null };
        expect(deserializeServiceRequest(serializeServiceRequest(noAuth)).auth).toBeNull();

        const route = {
            version: ROUTE_ENVELOPE_VERSION,
            targetService: 'couchdb.local',
            senderDeviceId: 'obsidian-abc',
            sealedRequest: new Uint8Array([1, 2, 3]),
            replyPubkey: new Uint8Array(1216).fill(9),
            nonce: new Uint8Array(12).fill(4),
            sentAtUnix: 1790000000,
            ttlSeconds: 300,
        };
        expect(deserializeRouteEnvelope(serializeRouteEnvelope(route))).toEqual(route);

        const resp = {
            version: SERVICE_ENVELOPE_VERSION,
            status: 404,
            headers: [['content-type', 'text/plain']] as [string, string][],
            body: new TextEncoder().encode('nope'),
        };
        expect(deserializeServiceResponse(serializeServiceResponse(resp))).toEqual(resp);
    });

    it('seals the full two-layer chain so only the service can read the request', () => {
        const gatewayKp = generateKeypair();
        const serviceKp = generateKeypair();
        const replyKp = generateKeypair();
        const body = new TextEncoder().encode('{"secret":"payload"}');

        const wire = sealRouteEnvelopeV2(
            'PUT',
            '/obsidian-vault/doc1',
            body,
            [['content-type', 'application/json']],
            'couchdb.local',
            gatewayKp.publicKey,
            serviceKp.publicKey,
            replyKp.publicKey,
            'obsidian-dev-7'
        );

        const outer = deserializeHybridSealed(wire);
        const routePlain = open(outer.kemOutput, outer.ciphertext, gatewayKp.secretKey, ROUTE_REQUEST_INFO);
        const route = deserializeRouteEnvelope(unpadFrame(routePlain));
        expect(route.version).toBe(ROUTE_ENVELOPE_VERSION);
        expect(route.targetService).toBe('couchdb.local');
        expect(route.senderDeviceId).toBe('obsidian-dev-7');

        // The gateway key must NOT open the inner layer (wrong key AND info).
        const inner = deserializeHybridSealed(route.sealedRequest);
        expect(() => open(inner.kemOutput, inner.ciphertext, gatewayKp.secretKey, ROUTE_REQUEST_INFO)).toThrow();

        const svcPlain = open(inner.kemOutput, inner.ciphertext, serviceKp.secretKey, SERVICE_REQUEST_INFO);
        const svcReq = deserializeServiceRequest(unpadFrame(svcPlain));
        expect(svcReq.method).toBe('PUT');
        expect(svcReq.pathAndQuery).toBe('/obsidian-vault/doc1');
        expect(new TextDecoder().decode(svcReq.body)).toBe('{"secret":"payload"}');
        expect(svcReq.headers).toEqual([['content-type', 'application/json']]);
    });

    it('opens a ServiceResponse sealed to the reply key and rejects cross-info', () => {
        const replyKp = generateKeypair();
        const resp = {
            version: SERVICE_ENVELOPE_VERSION,
            status: 201,
            headers: [] as [string, string][],
            body: new TextEncoder().encode('{"ok":true}'),
        };
        const frame = padToBucketFrame(serializeServiceResponse(resp));
        const sealed = seal(replyKp.publicKey, SERVICE_RESPONSE_INFO, new Uint8Array(0), frame);

        const opened = open(sealed.kemOutput, sealed.ciphertext, replyKp.secretKey, SERVICE_RESPONSE_INFO);
        const decoded = deserializeServiceResponse(unpadFrame(opened));
        expect(decoded.status).toBe(201);
        expect(new TextDecoder().decode(decoded.body)).toBe('{"ok":true}');

        // A different domain separator must never open v2 ciphertext.
        expect(() => open(sealed.kemOutput, sealed.ciphertext, replyKp.secretKey, ROUTE_REQUEST_INFO)).toThrow();
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

    it('createSecureWebFetch performs full request-response E2EE roundtrip (v2 two-layer)', async () => {
        const gatewayKp = generateKeypair();
        const serviceKp = generateKeypair();
        const b64Pk = encodeBase64(gatewayKp.publicKey);

        const originalFetch = globalThis.fetch;
        globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = input.toString();
            if (url.includes('/.well-known/gateway-pubkey')) {
                return new Response(
                    JSON.stringify({
                        pubkey: b64Pk,
                        public_key_hex: bytesToHex(gatewayKp.publicKey),
                        hosts: ['couchdb.local'],
                        revoked: [],
                        services: {
                            'couchdb.local': { pubkey_hex: bytesToHex(serviceKp.publicKey) },
                        },
                    }),
                    { status: 200, headers: { 'content-type': 'application/json' } }
                );
            }

            if (url.includes('/gateway/e2e-envelope')) {
                // --- Simulate the TRUE-E2E gateway (opaque router) ---
                const bodyBytes = new Uint8Array(init?.body as ArrayBuffer);

                // Router: opens ONLY the outer RouteEnvelope with the gateway key.
                const sealedReq = deserializeHybridSealed(bodyBytes);
                const routePlain = open(sealedReq.kemOutput, sealedReq.ciphertext, gatewayKp.secretKey, ROUTE_REQUEST_INFO);
                const route = deserializeRouteEnvelope(unpadFrame(routePlain));
                expect(route.version).toBe(ROUTE_ENVELOPE_VERSION);
                expect(route.targetService).toBe('couchdb.local');
                expect(route.ttlSeconds).toBe(300);
                expect(route.replyPubkey.length).toBe(XWING_PUBLIC_KEY_SIZE);

                // Service: opens the inner ServiceRequest with the SERVICE key.
                const innerSealed = deserializeHybridSealed(route.sealedRequest);
                const svcPlain = open(innerSealed.kemOutput, innerSealed.ciphertext, serviceKp.secretKey, SERVICE_REQUEST_INFO);
                const svcReq = deserializeServiceRequest(unpadFrame(svcPlain));
                expect(svcReq.version).toBe(SERVICE_ENVELOPE_VERSION);
                expect(svcReq.method).toBe('GET');
                expect(svcReq.pathAndQuery).toBe('/obsidian-livesync/doc1');
                // The router must never see these — they exist only in the inner layer:
                expect(svcReq.headers.some(([k]) => k === 'x-reply-pubkey')).toBe(false);
                expect(svcReq.auth).toBeNull();

                // Service seals ServiceResponse directly to the client's reply key.
                const respPayload = new TextEncoder().encode('{"ok":true,"rev":"1-abc"}');
                const respFrame = padToBucketFrame(
                    serializeServiceResponse({
                        version: SERVICE_ENVELOPE_VERSION,
                        status: 200,
                        headers: [['content-type', 'application/json']],
                        body: respPayload,
                    })
                );
                const sealedResp = seal(route.replyPubkey, SERVICE_RESPONSE_INFO, new Uint8Array(0), respFrame);
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
