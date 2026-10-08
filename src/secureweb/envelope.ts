/**
 * SecureWeb — Zero-Knowledge End-to-End Encryption Envelope Transport
 *
 * Implements the pure TypeScript Post-Quantum X-Wing GatewayEnvelope
 * sealing and opening layer for Self-Hosted LiveSync synchronisation
 * through SecureWeb routers with strict zero-plaintext fallback.
 */

import {
    calculatePadLen,
    padBody,
    unpadBody,
    serializeGatewayEnvelope,
    deserializeHybridSealed,
    deserializeGatewayHttpResponse,
    serializeHybridSealed,
    type GatewayEnvelope,
    GATEWAY_ENVELOPE_VERSION,
} from './codec';
import { generateKeypair, XWING_PUBLIC_KEY_SIZE } from './xwing';
import { seal, open, GATEWAY_REQUEST_INFO, GATEWAY_RESPONSE_INFO } from './hpke';

export interface GatewayPubkeyMetadata {
    pubkey: string;
    suite?: string;
    public_key_hex?: string;
    public_key_base64?: string;
    hosts: string[];
    ttl_seconds?: number;
    revoked: string[];
}

export interface SecureWebTransportConfig {
    gatewayUrl: string;
    targetHost: string;
    deviceId?: string;
    passkeyToken?: string;
    networkFetch?: typeof fetch;
}

export class SecureWebEnvelopeError extends Error {
    constructor(message: string) {
        super(`[SecureWeb Envelope] ${message}`);
        this.name = 'SecureWebEnvelopeError';
    }
}

/** Generate a wire UUID using the Web Crypto API available on older mobile clients. */
export function createDeviceId(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function checkCancellation(signal?: AbortSignal | null): void {
    if (signal?.aborted) {
        throw signal.reason ?? new DOMException('The request was aborted', 'AbortError');
    }
}

const pubkeyCache = new Map<string, { metadata: GatewayPubkeyMetadata; fetchedAt: number }>();

export function clearPubkeyCache() {
    pubkeyCache.clear();
}

/**
 * Check whether a target host matches the gateway allowed hosts list.
 */
export function isHostAllowed(targetHost: string, allowedHosts: string[]): boolean {
    const target = targetHost.trim().toLowerCase();
    if (!target) {
        return false;
    }
    return allowedHosts.some((h) => {
        const allowed = h.trim().toLowerCase();
        if (allowed === '*' || allowed === target) {
            return true;
        }
        if (allowed.startsWith('*.') && target.endsWith(allowed.substring(1))) {
            return true;
        }
        if (target.endsWith('.' + allowed)) {
            return true;
        }
        return false;
    });
}

/**
 * Check whether a gateway public key has been revoked.
 */
export function isKeyRevoked(key: string, revokedKeys: string[]): boolean {
    const trimmed = key.trim().toLowerCase();
    if (!trimmed) {
        return false;
    }
    return revokedKeys.some((r) => r.trim().toLowerCase() === trimmed);
}

/**
 * Decode base64 or hex string into Uint8Array.
 */
export function decodeKeyBytes(keyStr: string): Uint8Array {
    const clean = keyStr.trim();
    // Check if hex
    if (/^[0-9a-fA-F]+$/.test(clean) && clean.length === XWING_PUBLIC_KEY_SIZE * 2) {
        const bytes = new Uint8Array(clean.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    // Otherwise base64
    try {
        let b64 = clean.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4 !== 0) {
            b64 += '=';
        }
        if (typeof atob === 'function') {
            const bin = atob(b64);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) {
                bytes[i] = bin.charCodeAt(i);
            }
            return bytes;
        } else if (typeof Buffer !== 'undefined') {
            return new Uint8Array(Buffer.from(b64, 'base64'));
        }
    } catch {
        // Fall through
    }

    throw new SecureWebEnvelopeError(`Invalid public key format: cannot parse ${keyStr.substring(0, 32)}...`);
}

/**
 * Encode Uint8Array into base64 string.
 */
export function encodeBase64(bytes: Uint8Array): string {
    if (typeof btoa === 'function') {
        let bin = '';
        for (let i = 0; i < bytes.length; i++) {
            bin += String.fromCharCode(bytes[i]);
        }
        return btoa(bin);
    } else if (typeof Buffer !== 'undefined') {
        return Buffer.from(bytes).toString('base64');
    }
    // Fallback base64 encoder
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let out = '';
    let i = 0;
    while (i < bytes.length) {
        const b0 = bytes[i++];
        const b1 = i < bytes.length ? bytes[i++] : 0;
        const b2 = i < bytes.length ? bytes[i++] : 0;
        const n = (b0 << 16) | (b1 << 8) | b2;
        out += chars[(n >> 18) & 63];
        out += chars[(n >> 12) & 63];
        out += i > bytes.length + 1 ? '=' : chars[(n >> 6) & 63];
        out += i > bytes.length ? '=' : chars[n & 63];
    }
    return out;
}

/**
 * Fetch the active gateway public key metadata from the discovery endpoint.
 */
export async function fetchGatewayPubkey(
    originUrl: string,
    networkFetch: typeof fetch = fetch,
    signal?: AbortSignal | null
): Promise<GatewayPubkeyMetadata | null> {
    const origin = new URL(originUrl).origin;
    const now = Date.now();
    const cached = pubkeyCache.get(origin);
    if (cached && now - cached.fetchedAt < (cached.metadata.ttl_seconds || 1800) * 1000) {
        return cached.metadata;
    }

    try {
        const discoveryUrl = new URL('/.well-known/gateway-pubkey', originUrl).toString();
        const response = await networkFetch(discoveryUrl, {
            headers: { Accept: 'application/json' },
            cache: 'no-cache',
            signal,
        });

        if (!response.ok) {
            return null;
        }

        const data = (await response.json()) as GatewayPubkeyMetadata;
        pubkeyCache.set(origin, { metadata: data, fetchedAt: now });
        return data;
    } catch {
        return null;
    }
}

/**
 * Construct and seal a GatewayEnvelope payload for dispatch to the router.
 *
 * @returns bincode-serialized HybridSealed bytes
 */
export async function sealGatewayEnvelope(
    method: string,
    pathAndQuery: string,
    body: Uint8Array,
    headers: [string, string][],
    targetHost: string,
    gatewayPubkey: Uint8Array | string,
    deviceId: string
): Promise<Uint8Array> {
    const pkBytes = typeof gatewayPubkey === 'string' ? decodeKeyBytes(gatewayPubkey) : gatewayPubkey;
    if (pkBytes.length !== XWING_PUBLIC_KEY_SIZE) {
        throw new SecureWebEnvelopeError(`Invalid gateway public key size: expected ${XWING_PUBLIC_KEY_SIZE}, got ${pkBytes.length}`);
    }

    // 1. Calculate bucket padding
    const padLen = calculatePadLen(body.length);
    const paddedBody = padBody(body, padLen);

    // 2. Generate random 12-byte nonce
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);

    // 3. Assemble GatewayEnvelope
    const envelope: GatewayEnvelope = {
        version: GATEWAY_ENVELOPE_VERSION,
        senderDeviceId: deviceId,
        targetHost,
        method: method.toUpperCase(),
        pathAndQuery,
        headers,
        body: paddedBody,
        nonce,
        padLen,
    };

    // 4. Bincode 1.3 serialize inner plaintext
    const plaintext = serializeGatewayEnvelope(envelope);

    // 5. HPKE Base Mode seal with X-Wing KEM
    const sealed = seal(pkBytes, GATEWAY_REQUEST_INFO, new Uint8Array(0), plaintext);

    // 6. Bincode 1.3 serialize outer HybridSealed wire frame
    return await Promise.resolve(serializeHybridSealed(sealed));
}

/**
 * Creates a custom fetch handler for PouchDB replication through the SecureWeb envelope plane
 * with zero-plaintext fallback (fails explicitly on encryption/authorization failure).
 */
export function createSecureWebFetch(config: SecureWebTransportConfig): typeof fetch {
    const devId = config.deviceId || createDeviceId();
    const networkFetch = config.networkFetch ?? fetch;

    return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        checkCancellation(init?.signal);
        const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
        const method = (init?.method || (typeof input === 'object' && 'method' in input ? input.method : 'GET') || 'GET').toUpperCase();

        const urlObj = new URL(urlStr);
        // The full URL is <gateway>/gateway/e2e-envelope/<db>/<doc>…: the
        // envelope endpoint prefix must NOT be part of the inner path that
        // is sealed and dispatched to the terminator. Strip it so the
        // gateway routes the opened envelope to the exact CouchDB surface
        // the client intended.
        const ENVELOPE_PREFIX = '/gateway/e2e-envelope';
        let basePath = urlObj.pathname;
        if (basePath.startsWith(ENVELOPE_PREFIX)) {
            basePath = basePath.slice(ENVELOPE_PREFIX.length);
        }
        if (!basePath.startsWith('/')) {
            basePath = '/' + basePath;
        }
        const pathAndQuery = basePath + urlObj.search;

        // Extract body bytes
        let bodyBytes = new Uint8Array(0);
        if (init?.body) {
            if (typeof init.body === 'string') {
                bodyBytes = new TextEncoder().encode(init.body);
            } else if (init.body instanceof ArrayBuffer) {
                bodyBytes = new Uint8Array(init.body);
            } else if (ArrayBuffer.isView(init.body)) {
                bodyBytes = new Uint8Array(init.body.buffer, init.body.byteOffset, init.body.byteLength);
            }
        }

        // Extract headers
        const headerList: [string, string][] = [];
        if (init?.headers) {
            if (init.headers instanceof Headers) {
                init.headers.forEach((v, k) => {
                    headerList.push([k.toLowerCase(), v]);
                });
            } else if (Array.isArray(init.headers)) {
                init.headers.forEach(([k, v]) => {
                    headerList.push([k.toLowerCase(), v]);
                });
            } else {
                Object.entries(init.headers).forEach(([k, v]) => {
                    headerList.push([k.toLowerCase(), String(v)]);
                });
            }
        }

        if (config.passkeyToken) {
            headerList.push(['authorization', `Bearer ${config.passkeyToken}`]);
        }

        // 1. Fetch gateway public key metadata
        const pubkeyData = await fetchGatewayPubkey(config.gatewayUrl, networkFetch, init?.signal);
        checkCancellation(init?.signal);
        if (!pubkeyData) {
            throw new SecureWebEnvelopeError(`Cannot discover gateway public key at ${config.gatewayUrl}`);
        }

        const pubkeyRaw = pubkeyData.public_key_base64 || pubkeyData.public_key_hex || pubkeyData.pubkey;
        if (!pubkeyRaw) {
            throw new SecureWebEnvelopeError('Gateway discovery returned empty public key');
        }

        // 2. Validate host policy & revocation
        if (pubkeyData.hosts && !isHostAllowed(config.targetHost, pubkeyData.hosts)) {
            throw new SecureWebEnvelopeError(`Target host "${config.targetHost}" is not in gateway allowed hosts: ${pubkeyData.hosts.join(', ')}`);
        }

        if (pubkeyData.revoked && isKeyRevoked(pubkeyRaw, pubkeyData.revoked)) {
            throw new SecureWebEnvelopeError(`Gateway public key is revoked`);
        }

        // 3. Generate ephemeral reply keypair for post-quantum E2EE response
        const replyKp = generateKeypair();
        const replyPubkeyB64 = encodeBase64(replyKp.publicKey);
        headerList.push(['x-reply-pubkey', replyPubkeyB64]);

        // 4. Seal request envelope
        const sealedWireBytes = await sealGatewayEnvelope(
            method,
            pathAndQuery,
            bodyBytes,
            headerList,
            config.targetHost,
            pubkeyRaw,
            devId
        );

        // 5. POST to gateway envelope endpoint
        const envelopeEndpoint = new URL('/gateway/e2e-envelope', config.gatewayUrl).toString();
        const rawResponse = await networkFetch(envelopeEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/octet-stream',
                'X-Gateway-Envelope': '1',
            },
            body: sealedWireBytes as unknown as BodyInit,
            signal: init?.signal,
        });

        // If gateway returned an HTTP error without an encrypted payload, surface it
        if (!rawResponse.ok && rawResponse.headers.get('content-type') !== 'application/octet-stream') {
            return rawResponse;
        }

        // 6. Decrypt and unwrap encrypted response envelope
        const respBuffer = await rawResponse.arrayBuffer();
        const respBytes = new Uint8Array(respBuffer);

        if (respBytes.length === 0) {
            return rawResponse;
        }

        try {
            // Deserialize outer HybridSealed
            const sealedResponse = deserializeHybridSealed(respBytes);

            // Open HPKE ciphertext with ephemeral reply secret key
            const openedPlaintext = open(
                sealedResponse.kemOutput,
                sealedResponse.ciphertext,
                replyKp.secretKey,
                GATEWAY_RESPONSE_INFO
            );

            // Deserialize inner GatewayHttpResponse
            const httpResp = deserializeGatewayHttpResponse(openedPlaintext);

            // Unpad response body
            const unpaddedBody = unpadBody(httpResp.body, httpResp.padLen);

            // Construct synthetic Response
            const responseHeaders = new Headers();
            for (const [k, v] of httpResp.headers) {
                responseHeaders.set(k, v);
            }

            return new Response(unpaddedBody as unknown as BodyInit, {
                status: httpResp.status,
                headers: responseHeaders,
            });
        } catch (decryptErr) {
            throw new SecureWebEnvelopeError(`Failed to decrypt gateway response: ${decryptErr instanceof Error ? decryptErr.message : String(decryptErr)}`);
        }
    };
}
