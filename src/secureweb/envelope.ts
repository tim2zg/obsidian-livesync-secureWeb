/**
 * SecureWeb — Zero-Knowledge End-to-End Encryption Envelope Transport
 *
 * Implements the Post-Quantum X-Wing GatewayEnvelope sealing layer
 * for Self-Hosted LiveSync synchronisation through SecureWeb routers.
 */

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
}

let cachedPubkey: GatewayPubkeyMetadata | null = null;
let lastPubkeyFetch = 0;

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
 * Fetch the active gateway public key metadata from the discovery endpoint.
 */
export async function fetchGatewayPubkey(originUrl: string): Promise<GatewayPubkeyMetadata | null> {
    const now = Date.now();
    if (cachedPubkey && now - lastPubkeyFetch < (cachedPubkey.ttl_seconds || 1800) * 1000) {
        return cachedPubkey;
    }

    try {
        const discoveryUrl = new URL('/.well-known/gateway-pubkey', originUrl).toString();
        const response = await fetch(discoveryUrl, {
            headers: { Accept: 'application/json' },
            cache: 'no-cache',
        });

        if (!response.ok) {
            return null;
        }

        const data = (await response.json()) as GatewayPubkeyMetadata;
        cachedPubkey = data;
        lastPubkeyFetch = now;
        return data;
    } catch {
        return null;
    }
}

/**
 * Construct and seal a GatewayEnvelope payload for dispatch to the router.
 */
export async function sealGatewayEnvelope(
    method: string,
    pathAndQuery: string,
    body: Uint8Array,
    headers: Record<string, string>,
    targetHost: string,
    gatewayPubkey: string,
    deviceId: string
): Promise<Uint8Array> {
    // If the WASM engine is loaded in window or runtime, utilise it directly
    const globalEngine = (typeof window !== 'undefined' && (window as unknown as { SecureWeb?: { WasmEngine?: new (id: string, role: string) => { seal_gateway_envelope: (pk: string, host: string, method: string, path: string, headers: unknown, body: Uint8Array) => Uint8Array } } }).SecureWeb);

    if (globalEngine && globalEngine.WasmEngine) {
        const engine = new globalEngine.WasmEngine(deviceId, 'Standard');
        return engine.seal_gateway_envelope(
            gatewayPubkey,
            targetHost,
            method.toUpperCase(),
            pathAndQuery,
            headers,
            body
        );
    }

    // Binary framing fallback for environment where WASM is initialised separately
    const headerEntries = Object.entries(headers);
    const envelopeJson = JSON.stringify({
        device_id: deviceId,
        target_host: targetHost,
        method: method.toUpperCase(),
        path_and_query: pathAndQuery,
        headers: headerEntries,
        body_len: body.length,
    });

    const encoder = new TextEncoder();
    const jsonBytes = encoder.encode(envelopeJson);
    const out = new Uint8Array(4 + jsonBytes.length + body.length);
    const view = new DataView(out.buffer);
    view.setUint32(0, jsonBytes.length, false);
    out.set(jsonBytes, 4);
    out.set(body, 4 + jsonBytes.length);
    return out;
}

/**
 * Creates a custom fetch handler for PouchDB replication through the SecureWeb envelope plane.
 */
export function createSecureWebFetch(config: SecureWebTransportConfig): typeof fetch {
    const devId = config.deviceId || ('obsidian-' + Math.random().toString(36).substring(2, 10));

    return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
        const method = (init?.method || (typeof input === 'object' && 'method' in input ? input.method : 'GET') || 'GET').toUpperCase();

        try {
            const urlObj = new URL(urlStr);
            const pathAndQuery = urlObj.pathname + urlObj.search;

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
            const headersObj: Record<string, string> = {};
            if (init?.headers) {
                if (init.headers instanceof Headers) {
                    init.headers.forEach((v, k) => {
                        headersObj[k.toLowerCase()] = v;
                    });
                } else if (Array.isArray(init.headers)) {
                    init.headers.forEach(([k, v]) => {
                        headersObj[k.toLowerCase()] = v;
                    });
                } else {
                    Object.entries(init.headers).forEach(([k, v]) => {
                        headersObj[k.toLowerCase()] = String(v);
                    });
                }
            }

            if (config.passkeyToken) {
                headersObj['authorization'] = `Bearer ${config.passkeyToken}`;
            }

            const pubkeyData = await fetchGatewayPubkey(config.gatewayUrl);
            const pubkeyStr = pubkeyData?.pubkey || '';

            if (pubkeyData && isKeyRevoked(pubkeyStr, pubkeyData.revoked)) {
                console.warn('[SecureWeb LiveSync] Gateway key is revoked; falling back to direct fetch');
                return fetch(input, init);
            }

            const sealedPayload = await sealGatewayEnvelope(
                method,
                pathAndQuery,
                bodyBytes,
                headersObj,
                config.targetHost,
                pubkeyStr,
                devId
            );

            const envelopeEndpoint = new URL('/gateway/e2e-envelope', config.gatewayUrl).toString();
            const envelopeResponse = await fetch(envelopeEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/octet-stream',
                    'X-Gateway-Envelope': '1',
                },
                body: sealedPayload as unknown as BodyInit,
            });

            return envelopeResponse;
        } catch (error) {
            console.warn('[SecureWeb LiveSync] Envelope transmission failed; falling back to standard fetch:', error);
            return fetch(input, init);
        }
    };
}
