import { withBoundedCouchDBReads } from "./batchReads";
import { compatGlobal } from "@vrtmrz/livesync-commonlib/compat/common/coreEnvFunctions";
/**
 * SecureWeb — Zero-Knowledge End-to-End Encryption Envelope Transport
 *
 * Implements the pure TypeScript Post-Quantum X-Wing TRUE-E2E v2 transport
 * for Self-Hosted LiveSync synchronisation through SecureWeb routers: an
 * inner `ServiceRequest` sealed to the target service's own key plus an
 * outer `RouteEnvelope` sealed to the gateway key (opaque router). The
 * legacy v1 `GatewayEnvelope` plane was removed with the v1 cutover.
 */

import {
    deserializeHybridSealed,
    serializeHybridSealed,
    padToBucketFrame,
    unpadFrame,
    serializeServiceRequest,
    serializeRouteEnvelope,
    deserializeServiceResponse,
    ROUTE_ENVELOPE_VERSION,
    SERVICE_ENVELOPE_VERSION,
    type ServiceRequestEnvelope,
    type RouteEnvelopeV2,
} from './codec';
import { generateKeypair, XWING_PUBLIC_KEY_SIZE } from './xwing';
import {
    seal,
    open,
    ROUTE_REQUEST_INFO,
    SERVICE_REQUEST_INFO,
    SERVICE_RESPONSE_INFO,
} from './hpke';

export interface ServiceKeyMetadata {
    pubkey_hex?: string;
    pubkey_base64?: string;
    epoch?: number;
    key_attestation?: unknown;
    /** Relay registry UUID — required for the session exchange. */
    service_id?: string;
}

export interface GatewayPubkeyMetadata {
    pubkey: string;
    suite?: string;
    public_key_hex?: string;
    public_key_base64?: string;
    hosts: string[];
    ttl_seconds?: number;
    revoked: string[];
    /** True-E2E v2: per-service X-Wing public keys published by the gateway. */
    services?: Record<string, ServiceKeyMetadata>;
}

export interface SecureWebTransportConfig {
    gatewayUrl: string;
    networkFetch?: typeof fetch;
    /** Gateway service alias used for envelope routing. Resolved from the
     * gateway's published services map when omitted — never hardcoded. */
    targetHost?: string;
    /** Relay registry UUID of the target service (session exchange). Comes
     * from settings / setup link; resolved from discovery when omitted. */
    serviceId?: string;
    /** Path prefix of the configured gateway URI (e.g. "/couchdb.local"),
     * stripped from outgoing paths. Derived from `couchDB_URI`. */
    basePath?: string;
    deviceId?: string;
    passkeyToken?: string;
}

interface ResolvedService {
    alias: string;
    serviceId: string;
    pubkeyHex?: string;
}

/**
 * Resolve the target service from configuration, falling back to what the
 * gateway publishes: explicit service id ⇒ find its alias; explicit alias ⇒
 * its id; otherwise the sole published service. No deployment identifiers
 * are baked into the bundle.
 */
function resolveService(
    config: SecureWebTransportConfig,
    doc: GatewayPubkeyMetadata
): ResolvedService {
    const services = doc.services ?? {};
    const entries = Object.entries(services);
    const pick = (alias: string, meta: ServiceKeyMetadata): ResolvedService => ({
        alias,
        serviceId: String(meta.service_id ?? config.serviceId ?? ""),
        pubkeyHex: meta.pubkey_hex || meta.pubkey_base64,
    });
    if (config.serviceId) {
        const match = entries.find(([, meta]) => String(meta?.service_id ?? "") === config.serviceId);
        if (match) {
            return pick(match[0], match[1]);
        }
        if (config.targetHost && services[config.targetHost]) {
            return pick(config.targetHost, services[config.targetHost]);
        }
        return { alias: entries[0]?.[0] ?? "", serviceId: config.serviceId, pubkeyHex: entries[0]?.[1]?.pubkey_hex || entries[0]?.[1]?.pubkey_base64 };
    }
    if (config.targetHost) {
        const meta = services[config.targetHost];
        if (meta) {
            return pick(config.targetHost, meta);
        }
    }
    if (entries.length === 1) {
        return pick(entries[0][0], entries[0][1]);
    }
    throw new SecureWebEnvelopeError(
        "no target service configured — pass service=<uuid> via the setup link or settings, or configure a single-service gateway"
    );
}

export class SecureWebEnvelopeError extends Error {
    constructor(message: string) {
        super(`[SecureWeb Envelope] ${message}`);
        this.name = 'SecureWebEnvelopeError';
    }
}

const gatewayPubkeys = new Map<string, { metadata: GatewayPubkeyMetadata; fetchedAt: number }>();

export function clearPubkeyCache() {
    gatewayPubkeys.clear();
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
export async function fetchGatewayPubkey(originUrl: string, networkFetch?: typeof fetch): Promise<GatewayPubkeyMetadata | null> {
    const now = Date.now();
    const origin = new URL(originUrl).origin;
    const cached = gatewayPubkeys.get(origin);
    if (cached && now - cached.fetchedAt < (cached.metadata.ttl_seconds || 1800) * 1000) {
        return cached.metadata;
    }

    try {
        const discoveryUrl = new URL('/.well-known/gateway-pubkey', originUrl).toString();
        let data: GatewayPubkeyMetadata;

        const hasObsidianRequest = typeof window !== 'undefined' && typeof (window as any).requestUrl === 'function';
        if (networkFetch) {
            const response = await networkFetch(discoveryUrl, { headers: { Accept: 'application/json' }, cache: 'no-cache' });
            if (!response.ok) return null;
            data = await response.json() as GatewayPubkeyMetadata;
        } else if (hasObsidianRequest) {
            const res = await (window as any).requestUrl({
                url: discoveryUrl,
                headers: { Accept: 'application/json' },
                throw: false,
            });
            if (res.status !== 200) {
                return null;
            }
            data = (typeof res.json === 'object' && res.json !== null ? res.json : JSON.parse(res.text)) as GatewayPubkeyMetadata;
        } else {
            const response = await fetch(discoveryUrl, {
                headers: { Accept: 'application/json' },
                cache: 'no-cache',
            });
            if (!response.ok) {
                return null;
            }
            data = (await response.json()) as GatewayPubkeyMetadata;
        }

        gatewayPubkeys.set(origin, { metadata: data, fetchedAt: now });
        return data;
    } catch {
        return null;
    }
}

/**
 * Construct the TRUE-E2E v2 two-layer wire payload.
 *
 * Layer 1 (inner): `ServiceRequest` sealed to the TARGET SERVICE's key —
 * only the terminator can read method/path/headers/body.
 * Layer 2 (outer): `RouteEnvelope` sealed to the gateway key — the router
 * learns only target_service/sender/freshness metadata plus opaque bytes.
 *
 * @returns bincode-serialized HybridSealed(RouteEnvelope) bytes to POST
 */
export function sealRouteEnvelopeV2(
    method: string,
    pathAndQuery: string,
    body: Uint8Array,
    headers: [string, string][],
    targetService: string,
    gatewayPubkey: Uint8Array | string,
    servicePubkey: Uint8Array | string,
    replyPubkey: Uint8Array,
    deviceId: string
): Uint8Array {
    const gwPk = typeof gatewayPubkey === 'string' ? decodeKeyBytes(gatewayPubkey) : gatewayPubkey;
    const svcPk = typeof servicePubkey === 'string' ? decodeKeyBytes(servicePubkey) : servicePubkey;
    if (gwPk.length !== XWING_PUBLIC_KEY_SIZE) {
        throw new SecureWebEnvelopeError(`Invalid gateway public key size: expected ${XWING_PUBLIC_KEY_SIZE}, got ${gwPk.length}`);
    }
    if (svcPk.length !== XWING_PUBLIC_KEY_SIZE) {
        throw new SecureWebEnvelopeError(`Invalid service public key size: expected ${XWING_PUBLIC_KEY_SIZE}, got ${svcPk.length}`);
    }
    if (replyPubkey.length !== XWING_PUBLIC_KEY_SIZE) {
        throw new SecureWebEnvelopeError(`Invalid reply public key size: expected ${XWING_PUBLIC_KEY_SIZE}, got ${replyPubkey.length}`);
    }

    // Inner: ServiceRequest -> service key (SWP1-framed).
    const svcReq: ServiceRequestEnvelope = {
        version: SERVICE_ENVELOPE_VERSION,
        method: method.toUpperCase(),
        pathAndQuery,
        headers,
        body,
        auth: null,
    };
    const svcPlain = padToBucketFrame(serializeServiceRequest(svcReq));
    const sealedSvc = seal(svcPk, SERVICE_REQUEST_INFO, new Uint8Array(0), svcPlain);
    const sealedReqBytes = serializeHybridSealed(sealedSvc);

    // Outer: RouteEnvelope -> gateway key (SWP1-framed).
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    const route: RouteEnvelopeV2 = {
        version: ROUTE_ENVELOPE_VERSION,
        targetService,
        senderDeviceId: deviceId,
        sealedRequest: sealedReqBytes,
        replyPubkey,
        nonce,
        sentAtUnix: Math.floor(Date.now() / 1000),
        ttlSeconds: 300,
    };
    const routePlain = padToBucketFrame(serializeRouteEnvelope(route));
    const sealedRoute = seal(gwPk, ROUTE_REQUEST_INFO, new Uint8Array(0), routePlain);
    return serializeHybridSealed(sealedRoute);
}

export function createDeviceId(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

let cachedDeviceId: string | null = null;

export function getStableDeviceId(configured?: string): string {
    if (configured && configured.trim().length > 0) return configured.trim();
    if (!cachedDeviceId) {
        try {
            cachedDeviceId = (typeof localStorage !== 'undefined' && localStorage.getItem('secureweb_client_device_id')) || null;
            if (!cachedDeviceId) {
                cachedDeviceId = createDeviceId();
                if (typeof localStorage !== 'undefined') {
                    localStorage.setItem('secureweb_client_device_id', cachedDeviceId);
                }
            }
        } catch {
            cachedDeviceId = createDeviceId();
        }
    }
    return cachedDeviceId;
}

type ServiceSessionCache = { key: string; jwt: string; expMs: number };
let serviceSessionCache: ServiceSessionCache | null = null;
// Single-flight: PouchDB fires hundreds of sealed fetches in parallel at
// startup — without sharing, each opens its own exchange request and the
// storm (500/s observed) stalls the tunnel and freezes the renderer.
let serviceSessionInflight: { key: string; promise: Promise<string> } | null = null;

function invalidateServiceSession(): void {
    serviceSessionCache = null;
    serviceSessionInflight = null;
}

/**
 * Exchange the configured long-lived app secret (`swt_v2_…` in
 * `couchDB_PASSWORD`) for a bounded service-session JWT via the gateway's
 * same-origin relay proxy (`POST /gateway/service-session`). Sessions last
 * up to 8 hours; this refreshes silently 60 s before expiry and drops the
 * cache on auth failures so the next request re-exchanges.
 */
async function ensureServiceSession(
    config: SecureWebTransportConfig,
    overrideSecret?: string
): Promise<string> {
    const secret = overrideSecret ?? config.passkeyToken;
    if (!secret) {
        throw new SecureWebEnvelopeError('no app token configured (couchDB_PASSWORD)');
    }
    const cacheKey = `${config.gatewayUrl}|${config.serviceId ?? config.targetHost ?? "auto"}|${secret}`;
    const now = Date.now();
    if (
        serviceSessionCache &&
        serviceSessionCache.key === cacheKey &&
        now < serviceSessionCache.expMs - 60_000
    ) {
        return serviceSessionCache.jwt;
    }
    if (serviceSessionInflight && serviceSessionInflight.key === cacheKey) {
        return serviceSessionInflight.promise;
    }

    const flight = (async () => {
        const doc = await fetchGatewayPubkey(config.gatewayUrl, config.networkFetch);
    const serviceId = doc ? resolveService(config, doc).serviceId : config.serviceId;
    if (!serviceId) {
        throw new SecureWebEnvelopeError(
            `gateway does not publish a resolvable service — cannot determine the session-exchange target`
        );
    }

    const exchangeUrl = new URL('/gateway/service-session', config.gatewayUrl).toString();
    // The secret rides in the BODY: Electron/Obsidian network layers have
    // inconsistent Authorization handling, and bodies are proven to arrive
    // intact (the envelope POSTs use the same path). The gateway strips
    // `app_secret` before forwarding to the relay.
    const exchangeBody = JSON.stringify({
        service_id: serviceId,
        scopes: ['sync:read', 'sync:write'],
        ttl_seconds: 28800,
        app_secret: secret,
    });
    const exchangeHeaders: Record<string, string> = {
        'Content-Type': 'application/json',
    };

    let data: unknown;
    // Plain RAW fetch, captured before any interceptor was installed
    // (fallback: bare fetch in node/tests). The sealed flow must never be
    // re-entered by its own session exchange — the trace showed exactly
    // that recursion once (500 [exchange] BEGIN/s, zero ENDs, frozen
    // renderer), so this call is structurally bypass-proof.
    {
        // Trace the credential identity (hash prefix only — never the value):
        // a relay 401 with the wrong prefix means settings-resurrection sent
        // a stale token instead of the configured secret.
        try {
            const digest = await crypto.subtle.digest(
                'SHA-256',
                new TextEncoder().encode(secret)
            );
            const prefix = Array.from(new Uint8Array(digest))
                .slice(0, 6)
                .map((b) => b.toString(16).padStart(2, '0'))
                .join('');
            transportLog(`[exchange] BEGIN ttl=28800 secret_sha=${prefix}`);
        } catch {
            transportLog(`[exchange] BEGIN ttl=28800 secret_sha=?`);
        }
        const rawFetch: typeof fetch = config.networkFetch ??
            (compatGlobal as any).__secureWebRawFetch ?? fetch;
        const exchangeOnce = async (): Promise<Response> => {
            const controller =
                typeof AbortController !== 'undefined' ? new AbortController() : null;
            const timer =
                controller !== null ? compatGlobal.setTimeout(() => controller.abort(), 15_000) : null;
            try {
                return await rawFetch(exchangeUrl, {
                    method: 'POST',
                    headers: exchangeHeaders,
                    body: exchangeBody,
                    signal: controller?.signal,
                });
            } finally {
                if (timer !== null) compatGlobal.clearTimeout(timer);
            }
        };
        let res: Response;
        try {
            res = await exchangeOnce();
            if (res.status === 502 || res.status === 503 || res.status === 504) {
                // Transient edge/relay hiccup (e.g. cloudflared blip): retry once.
                transportLog(`[exchange] transient ${res.status}, retrying once`);
                res = await exchangeOnce();
            }
        } catch (err) {
            transportLog(
                `[exchange] network error (${err instanceof Error ? err.message : String(err)}), retrying once`
            );
            res = await exchangeOnce();
        }
        transportLog(`[exchange] END status=${res.status}`);
        if (!res.ok) {
            // Surface the server's reason (gateway/relay now answer JSON).
            let reason = '';
            try {
                const bodyText = await res.text();
                try {
                    const parsed = JSON.parse(bodyText);
                    const pe = parsed?.error;
                    reason =
                        pe && typeof pe === 'object'
                            ? pe.message || pe.reason || JSON.stringify(pe)
                            : pe || parsed?.reason || '';
                } catch {
                    reason = bodyText;
                }
            } catch {
                /* body unreadable — status alone must suffice */
            }
            throw new SecureWebEnvelopeError(
                `service session exchange failed: HTTP ${res.status}${reason ? ` — ${String(reason).slice(0, 300)}` : ''}`
            );
        }
        data = await res.json();
    }

    const session = data as { access_token?: string; expires_in?: number } | null;
    if (!session?.access_token) {
        throw new SecureWebEnvelopeError('service session exchange returned no access token');
    }
    serviceSessionCache = {
        key: cacheKey,
        jwt: String(session.access_token),
        expMs: now + (Number(session.expires_in) || 900) * 1000,
    };
    return serviceSessionCache.jwt;
    })();
    serviceSessionInflight = { key: cacheKey, promise: flight };
    try {
        return await flight;
    } finally {
        if (serviceSessionInflight && serviceSessionInflight.key === cacheKey) {
            serviceSessionInflight = null;
        }
    }
}

/**
 * Creates a custom fetch handler for PouchDB replication through the SecureWeb envelope plane
 * with zero-plaintext fallback (fails explicitly on encryption/authorization failure).
 */
/**
 * Runtime registry of gateway hosts. The transport must never bake a
 * deployment domain into the bundle: hosts come from plugin settings
 * (`couchDB_URI`, read live) and from the one-tap setup link, which
 * registers its gateway before the settings are even saved (so the very
 * first connection test already rides the sealed transport).
 */
const registeredGatewayHosts = new Set<string>();

export function registerGatewayHost(raw: string): void {
    if (!raw) return;
    try {
        // Livesync profile URIs are "sls+https://…" connection strings; the
        // transport wants the plain URL underneath.
        const plain = raw.replace(/^sls\+/, "");
        const host = new URL(plain.startsWith("http") ? plain : `https://${plain}`).host;
        if (host) registeredGatewayHosts.add(host);
    } catch {
        /* not a URL — ignore */
    }
}

export function isRegisteredGatewayHost(urlStr: string): boolean {
    try {
        const url = new URL(urlStr.replace(/^secureweb:/, 'https:'));
        return registeredGatewayHosts.has(url.host);
    } catch { return false; }
}

export function isGatewayInfrastructureRequest(input: string | Request | URL, init?: RequestInit): boolean {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    return url.pathname.startsWith('/.well-known/') || url.pathname.startsWith('/transparency/')
        || ['/gateway/service-session', '/healthz', '/metrics'].includes(url.pathname)
        || (url.pathname === '/gateway/e2e-envelope'
            && new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)).get('x-gateway-envelope') === '2');
}

/**
 * Register every gateway host the plugin configuration knows about: the
 * top-level `couchDB_URI` plus all *plaintext* remote-configuration
 * profiles (their `uri` is a connection string, possibly with credentials).
 * Encrypted profiles are skipped — their contents can't be inspected
 * without the settings key.
 */
export function registerConfiguredGatewayHosts(settings: any): void {
    try {
        const explicit = (uri: string) => uri.startsWith('secureweb:') || uri.includes('/gateway/e2e-envelope');
        const profiles = settings?.remoteConfigurations || {};
        const active = profiles[settings?.activeConfigurationId];
        const isGatewayProfile = (profile: any) => profile?.id === 'secureweb'
            || profile?.name === 'SecureWeb' || (typeof profile?.uri === 'string' && explicit(profile.uri));
        for (const [id, profile] of Object.entries<any>(profiles)) {
            if (profile?.uri && profile.isEncrypted !== true && (id === 'secureweb' || isGatewayProfile(profile))) registerGatewayHost(profile.uri);
        }
        const uri = settings?.couchDB_URI;
        if (uri && (explicit(uri) || isGatewayProfile(active)
            || (!active && (settings?.secureWebEnabled || settings?.secureWebServiceId)))) registerGatewayHost(uri);
    } catch { /* Configuration discovery must not break unrelated requests. */ }
}

let secureWebSettingsProvider: (() => any) | null = null;

/** Wire the plugin's live settings into the transport helpers. */
export function setSecureWebSettingsProvider(provider: () => any): void {
    secureWebSettingsProvider = provider;
}

/**
 * True when a URL targets the configured gateway. Registers hosts from the
 * live plugin settings first, so the answer stays correct even when the
 * caller supplied the URL from a settings draft rather than a saved field.
 */
export function shouldSealConfiguredUrl(url: string): boolean {
    if (typeof secureWebSettingsProvider === "function") {
        try {
            registerConfiguredGatewayHosts(secureWebSettingsProvider());
        } catch {
            /* ignore */
        }
    }
    return isRegisteredGatewayHost(String(url));
}

/**
 * Sealed counterpart of Obsidian's `requestUrl` for code paths that import
 * it directly (the setup wizard's connection probe via ObsHttpHandler).
 * Gateway-bound URLs ride the already-installed sealed fetch interceptor;
 * callers must check `shouldSealConfiguredUrl` first and fall back to the
 * real `requestUrl` otherwise.
 */
export async function sealedRequestUrl(param: {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string | ArrayBuffer;
}): Promise<{
    status: number;
    headers: Record<string, string>;
    arrayBuffer: ArrayBuffer;
    text: string;
    json: unknown;
}> {
    const fetchImpl = (compatGlobal as any).fetch as typeof fetch;
    const resp = await fetchImpl(param.url, {
        method: (param.method || "GET").toUpperCase(),
        headers: param.headers,
        body: param.body as BodyInit | undefined,
    });
    const buf = await resp.arrayBuffer();
    const text = new TextDecoder().decode(buf);
    const headers: Record<string, string> = {};
    resp.headers.forEach((value: string, key: string) => {
        headers[key] = value;
    });
    let json: unknown = null;
    try {
        json = JSON.parse(text);
    } catch {
        json = null;
    }
    return { status: resp.status, headers, arrayBuffer: buf, text, json };
}

export function createSecureWebFetch(config: SecureWebTransportConfig): typeof fetch {
    const devId = getStableDeviceId(config.deviceId);

    return withBoundedCouchDBReads(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
        if (signal?.aborted) throw signal.reason ?? new DOMException('The request was aborted', 'AbortError');
        const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
        let method = (init?.method || (typeof input === 'object' && 'method' in input ? input.method : 'GET') || 'GET').toUpperCase();

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
        if (config.basePath && basePath.startsWith(config.basePath)) {
            basePath = basePath.slice(config.basePath.length);
        }
        if (!basePath.startsWith('/')) {
            basePath = '/' + basePath;
        }
        let pathAndQuery = basePath + urlObj.search;

        // Extract body bytes
        let bodyBytes = new Uint8Array(0);
        if (init?.body !== undefined && init?.body !== null) {
            const b = init.body;
            if (typeof b === 'string') {
                bodyBytes = new TextEncoder().encode(b);
            } else if (b instanceof ArrayBuffer) {
                bodyBytes = new Uint8Array(b);
            } else if (ArrayBuffer.isView(b)) {
                bodyBytes = new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
            }
        } else if (typeof input === 'object' && input instanceof Request) {
            try {
                const ab = await input.clone().arrayBuffer();
                if (ab.byteLength > 0) {
                    bodyBytes = new Uint8Array(ab);
                }
            } catch {
                // Ignore if body cannot be cloned
            }
        } else if (typeof input === 'object' && input !== null && 'body' in input && (input as any).body) {
            const b = (input as any).body;
            if (typeof b === 'string') {
                bodyBytes = new TextEncoder().encode(b);
            } else if (b instanceof ArrayBuffer) {
                bodyBytes = new Uint8Array(b);
            } else if (ArrayBuffer.isView(b)) {
                bodyBytes = new Uint8Array(b.buffer as ArrayBuffer, b.byteOffset, b.byteLength);
            }
        }
        // Special case: CouchDB / PouchDB allDocs with keys.
        // PouchDB dispatches POST /:db/_all_docs with {"keys": [...], "include_docs": ...}
        // when reading missing document chunks during vault materialization.
        // If the upstream router only allows GET on /:db/_all_docs, convert to
        // GET /:db/_all_docs?keys=[...]&include_docs=... which CouchDB natively supports.
        if (method === 'POST' && (basePath.endsWith('/_all_docs') || basePath.includes('/_all_docs')) && bodyBytes.length > 0) {
            try {
                const bodyText = new TextDecoder().decode(bodyBytes);
                const parsed = JSON.parse(bodyText);
                if (parsed && typeof parsed === 'object') {
                    const searchParams = new URLSearchParams(urlObj.search);
                    for (const [k, v] of Object.entries(parsed)) {
                        if (k === 'keys' && Array.isArray(v)) {
                            searchParams.set('keys', JSON.stringify(v));
                        } else if (typeof v === 'boolean' || typeof v === 'number' || typeof v === 'string') {
                            searchParams.set(k, String(v));
                        }
                    }
                    // Only convert to GET if the query string is short (<1500 chars).
                    // Large chunk batches (>1500 chars) must remain POST with body to avoid URL length limits.
                    const newQuery = searchParams.toString();
                    if (newQuery.length < 1500) {
                        method = 'GET';
                        pathAndQuery = basePath + (newQuery ? `?${newQuery}` : '');
                        bodyBytes = new Uint8Array(0);
                    }
                }
            } catch {
                // Non-JSON or malformed payload, retain POST
            }
        }

        // Extract and filter whitelisted headers
        const headerList: [string, string][] = [];
        // Matches common::SERVICE_WHITELISTED_HEADERS — the reply key is an
        // OUTER RouteEnvelope field in v2 and must never ride inner headers.
        const whitelistedHeaders = new Set([
            'content-type',
            'accept',
            'accept-language',
            'authorization',
            'x-request-id',
            'x-device-id',
            'cache-control',
            'if-none-match',
            'if-modified-since',
        ]);
        const addWhitelistedHeader = (k: string, v: string) => {
            const lower = k.toLowerCase();
            if (whitelistedHeaders.has(lower)) {
                headerList.push([lower, v]);
            }
        };

        const headersSource = init?.headers || (typeof input === 'object' && 'headers' in input ? input.headers : undefined);
        if (headersSource) {
            if (headersSource instanceof Headers) {
                headersSource.forEach((v, k) => addWhitelistedHeader(k, v));
            } else if (Array.isArray(headersSource)) {
                headersSource.forEach(([k, v]) => addWhitelistedHeader(k, v));
            } else {
                Object.entries(headersSource).forEach(([k, v]) => addWhitelistedHeader(k, String(v)));
            }
        }

        if (!headerList.some(([k]) => k === 'x-device-id')) {
            headerList.push(['x-device-id', devId]);
        }

        if (method === 'GET') {
            const ctIdx = headerList.findIndex(([k]) => k === 'content-type');
            if (ctIdx !== -1) {
                headerList.splice(ctIdx, 1);
            }
        }

        // 1. Fetch gateway public key metadata
        const pubkeyData = await fetchGatewayPubkey(config.gatewayUrl, config.networkFetch);
        if (!pubkeyData) {
            throw new SecureWebEnvelopeError(`Cannot discover gateway public key at ${config.gatewayUrl}`);
        }

        const pubkeyRaw = pubkeyData.public_key_base64 || pubkeyData.public_key_hex || pubkeyData.pubkey;
        if (!pubkeyRaw) {
            throw new SecureWebEnvelopeError('Gateway discovery returned empty public key');
        }

        // 2. Resolve the target service: configuration first (settings /
        // setup link), gateway discovery as the fallback.
        const resolvedService = resolveService(config, pubkeyData);

        // 3. Validate host policy & revocation
        if (pubkeyData.hosts && resolvedService.alias && !isHostAllowed(resolvedService.alias, pubkeyData.hosts)) {
            throw new SecureWebEnvelopeError(`Target host "${resolvedService.alias}" is not in gateway allowed hosts: ${pubkeyData.hosts.join(', ')}`);
        }

        if (pubkeyData.revoked && isKeyRevoked(pubkeyRaw, pubkeyData.revoked)) {
            throw new SecureWebEnvelopeError(`Gateway public key is revoked`);
        }

        // 4. Resolve the SERVICE key (true-E2E v2): the inner ServiceRequest
        // is sealed to the target service — the gateway can route but never
        // read method/path/headers/body.
        const servicePubkeyRaw = resolvedService.pubkeyHex;
        if (!servicePubkeyRaw) {
            throw new SecureWebEnvelopeError(
                `Service key for "${resolvedService.alias || resolvedService.serviceId}" is not published by the gateway — cannot seal (true-E2E requires it)`
            );
        }

        // Setup wizards (and PouchDB basic-auth configs) put the raw app
        // secret into the Authorization header before settings are saved —
        // Bearer or Basic (`user:secret`) form. Extract it as the exchange
        // credential; the header itself gets replaced by a bounded session
        // below. The Basic username is transport-irrelevant.
        let headerSecret: string | undefined;
        const preAuthIdx = headerList.findIndex(([k]) => k === 'authorization');
        if (preAuthIdx !== -1) {
            let raw = (headerList[preAuthIdx][1] || '').trim();
            const lower = raw.toLowerCase();
            if (lower.startsWith('bearer ')) {
                raw = raw.slice(7).trim();
            } else if (lower.startsWith('basic ')) {
                try {
                    const decoded = atob(raw.slice(6).trim());
                    const colon = decoded.indexOf(':');
                    raw = (colon >= 0 ? decoded.slice(colon + 1) : decoded).trim();
                } catch {
                    raw = '';
                }
            }
            if (raw.startsWith('swt_')) {
                headerSecret = raw;
            }
        }
        const effectiveSecret = headerSecret || config.passkeyToken;

        // 3.5 Authorization carries a BOUNDED service session, never the raw
        // secret: exchanged silently here (renewed before expiry).
        if (effectiveSecret) {
            const bearer = await ensureServiceSession(config, effectiveSecret);
            const authIdx = headerList.findIndex(([k]) => k === 'authorization');
            if (authIdx === -1) {
                headerList.push(['authorization', `Bearer ${bearer}`]);
            } else {
                headerList[authIdx] = ['authorization', `Bearer ${bearer}`];
            }
        }

        // 4. Generate ephemeral reply keypair — the SERVICE seals the response
        // to it (outer RouteEnvelope field, never an inner header).
        const replyKp = generateKeypair();

        // 5. Seal the two-layer v2 envelope
        const sealedWireBytes = sealRouteEnvelopeV2(
            method,
            pathAndQuery,
            bodyBytes,
            headerList,
            resolvedService.alias,
            pubkeyRaw,
            servicePubkeyRaw,
            replyKp.publicKey,
            devId
        );

        // 5. POST to gateway envelope endpoint
        const envelopeEndpoint = new URL('/gateway/e2e-envelope', config.gatewayUrl).toString();

        const hasObsidianRequest = !config.networkFetch && typeof window !== 'undefined' && typeof (window as any).requestUrl === 'function';
        let respBytes: Uint8Array;

        if (hasObsidianRequest) {
            const bodyBuf = (sealedWireBytes.byteOffset === 0 && sealedWireBytes.byteLength === sealedWireBytes.buffer.byteLength)
                ? sealedWireBytes.buffer
                : sealedWireBytes.buffer.slice(
                    sealedWireBytes.byteOffset,
                    sealedWireBytes.byteOffset + sealedWireBytes.byteLength
                );
            // Cloudflare edges throw transient 502/503/504 under chunk bursts.
            // Those are not real failures — back off and retry transparently so
            // heavy files don't surface as per-file sync errors.
            let reqRes: { headers: Record<string, string>; status: number; arrayBuffer: ArrayBuffer };
            for (let attempt = 0; ; attempt += 1) {
                reqRes = await (window as any).requestUrl({
                    url: envelopeEndpoint,
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/octet-stream',
                        'X-Gateway-Envelope': '2',
                    },
                    body: bodyBuf,
                    throw: false,
                });
                const ct0 = reqRes.headers ? (reqRes.headers['content-type'] || reqRes.headers['Content-Type'] || '') : '';
                const edgeFailure =
                    !String(ct0).includes('application/octet-stream') &&
                    (reqRes.status === 502 || reqRes.status === 503 || reqRes.status === 504);
                if (edgeFailure && attempt < 3) {
                    transportLog(`[envelope] edge ${reqRes.status}, retry ${attempt + 1}`);
                    await new Promise((resolve) => compatGlobal.setTimeout(resolve, 300 * (attempt + 1)));
                    continue;
                }
                break;
            }

            const ct = reqRes.headers ? (reqRes.headers['content-type'] || reqRes.headers['Content-Type'] || '') : '';
            const isEncrypted = ct.includes('application/octet-stream');
            respBytes = new Uint8Array(reqRes.arrayBuffer);

            if (reqRes.status >= 400 && !isEncrypted) {
                const respHeaders = new Headers();
                if (reqRes.headers) {
                    Object.entries(reqRes.headers).forEach(([k, v]) => {
                        respHeaders.set(k, String(v));
                    });
                }
                return new Response(respBytes as unknown as BodyInit, {
                    status: reqRes.status,
                    headers: respHeaders,
                });
            }
        } else {
            let rawResponse: Response;
            for (let attempt = 0; ; attempt += 1) {
                rawResponse = await (config.networkFetch ?? compatGlobal.fetch)(envelopeEndpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/octet-stream',
                        'X-Gateway-Envelope': '2',
                    },
                    body: sealedWireBytes as unknown as BodyInit,
                });
                const edgeFailure =
                    !rawResponse.ok &&
                    rawResponse.headers.get('content-type') !== 'application/octet-stream' &&
                    (rawResponse.status === 502 || rawResponse.status === 503 || rawResponse.status === 504);
                if (edgeFailure && attempt < 3) {
                    transportLog(`[envelope] edge ${rawResponse.status}, retry ${attempt + 1}`);
                    await new Promise((resolve) => compatGlobal.setTimeout(resolve, 300 * (attempt + 1)));
                    continue;
                }
                break;
            }

            if (!rawResponse.ok && rawResponse.headers.get('content-type') !== 'application/octet-stream') {
                return rawResponse;
            }

            const respBuffer = await rawResponse.arrayBuffer();
            respBytes = new Uint8Array(respBuffer);
        }

        if (respBytes.length === 0) {
            return new Response(new Uint8Array(0), { status: 200 });
        }

        try {
            // Deserialize outer HybridSealed
            const sealedResponse = deserializeHybridSealed(respBytes);

            // Open with the ephemeral reply secret key — the SERVICE sealed
            // this ServiceResponse directly to us (v2, no plaintext path).
            const openedFrame = open(
                sealedResponse.kemOutput,
                sealedResponse.ciphertext,
                replyKp.secretKey,
                SERVICE_RESPONSE_INFO
            );

            // Strip the SWP1 bucket frame, then deserialize ServiceResponse.
            // v2 bodies carry no padLen — padding lives in the frame.
            const httpResp = deserializeServiceResponse(unpadFrame(openedFrame));
            const unpaddedBody = httpResp.body;

            // Construct synthetic Response
            const responseHeaders = new Headers();
            for (const [k, v] of httpResp.headers) {
                responseHeaders.set(k, v);
            }
            if (!responseHeaders.has('access-control-allow-origin')) {
                responseHeaders.set('access-control-allow-origin', 'app://obsidian.md');
                responseHeaders.set('access-control-allow-credentials', 'true');
            }
            if (!responseHeaders.has('server')) {
                responseHeaders.set('server', 'CouchDB/3.5.2');
            }

            if (httpResp.status === 401 || httpResp.status === 403) {
                // Session expired or was revoked — drop it so the next
                // request silently re-exchanges before sealing.
                invalidateServiceSession();
            }
            return new Response(unpaddedBody as unknown as BodyInit, {
                status: httpResp.status,
                headers: responseHeaders,
            });
        } catch (decryptErr) {
            throw new SecureWebEnvelopeError(`Failed to decrypt gateway response: ${decryptErr instanceof Error ? decryptErr.message : String(decryptErr)}`);
        }
    });
}

export type SecureWebSettingsLike = {
    couchDB_URI?: string;
    couchDB_PASSWORD?: string;
};

// Hang forensics: the renderer can freeze before devtools open, so transport
// breadcrumbs are appended to durable sinks. Never throws, never blocks
// transport. Bounded to avoid unbounded growth.
let transportLogCount = 0;
const transportLogRing: string[] = [];
export function getTransportLog(): string[] {
    return [...transportLogRing];
}
export const transportLog = (line: string): void => {
    if (transportLogCount > 500) return;
    transportLogCount += 1;
    const stamped = `${new Date().toISOString()} ${line}`;
    transportLogRing.push(stamped);
    if (transportLogRing.length > 500) transportLogRing.shift();
    try {
        console.log(`[SecureWeb-trace] ${line}`);
    } catch {
        /* ignore */
    }
    try {
        const sink = (compatGlobal as any).__secureWebLogSink;
        if (typeof sink === "function") sink(stamped);
    } catch {
        /* ignore */
    }
    try {
        // localStorage survives the frozen/killed renderer.
        const ls = (compatGlobal as any).localStorage;
        if (ls && typeof ls.setItem === "function") {
            const prior = String(ls.getItem("sw-transport-log") || "");
            ls.setItem("sw-transport-log", (prior + stamped + "\n").slice(-16000));
        }
    } catch {
        /* ignore */
    }
    try {
        // File sink when Node's require is reachable in any form.
        const req =
            (compatGlobal as any).require ??
            (typeof require === "function" ? require : undefined);
        if (typeof req === "function") {
            const fs = req("fs");
            const path = req("path");
            const os = req("os");
            const target = path.join(os.tmpdir(), "secureweb-transport.log");
            fs.appendFileSync(target, stamped + "\r\n");
        }
    } catch {
        /* ignore */
    }
};

/**
 * Seal shim for `XMLHttpRequest`: PouchDB's HTTP adapter speaks XHR, which
 * bypasses any `window.fetch` interceptor. Under sealed-only mode those
 * direct requests die as blind-mode 404s (observed as livesync failing to
 * obtain the PBKDF2 Security Seed), so matching XHR calls are routed
 * through the same envelope transport and answered with synthesized
 * responses. `window.fetch` interception remains in place for fetch users.
 */
/**
 * Wrap Obsidian's `requestUrl` so plugin code paths that use it (the setup
 * wizard's "Test connection" probe, encryption-key init, and various
 * livesync internals) ride the sealed transport like fetch and XHR do.
 *
 * Gateway-bound URLs are sealed through the already-installed fetch
 * interceptor; everything else defers to the original implementation —
 * native `requestUrl` bypasses CORS and third parties rely on that, so
 * non-gateway traffic must never be re-routed through `fetch`.
 */
export function installSecureWebRequestUrlShim(getPlugin: () => any): () => void {
    if (typeof window === "undefined") return () => {};
    const win = window as any;
    if (typeof win.requestUrl !== "function") return () => {};
    win.__secureWebRequestUrlShimInstalled = true;
    const original = win.__secureWebRawRequestUrl ?? win.requestUrl.bind(win);
    win.__secureWebRawRequestUrl = original;

    const isGatewayBound = (rawUrl: string): boolean => {
        const urlStr = String(rawUrl);
        // Gateway infrastructure routes are plaintext by design — sealing
        // them would recurse into the sealed flow itself.
        if (
            urlStr.includes("/gateway/e2e-envelope") ||
            urlStr.includes("/gateway/stream") ||
            urlStr.includes("/gateway/service-session") ||
            urlStr.includes("/.well-known/") ||
            urlStr.includes("/transparency/") ||
            urlStr.includes("/healthz") ||
            urlStr.includes("/metrics")
        ) {
            return false;
        }
        try {
            const plugin = getPlugin();
            const settings = plugin?.core?.settings ?? plugin?.settings;
            registerConfiguredGatewayHosts(settings);
            return isRegisteredGatewayHost(urlStr);
        } catch {
            return false;
        }
    };

    const sealedRequest = async (req: any) => {
        const url = typeof req === "string" ? req : req?.url;
        if (typeof url !== "string" || !isGatewayBound(url) || typeof win.fetch !== "function") {
            return original(req);
        }
        try {
            transportLog(
                `[requesturl-shim] seal ${String(req?.method ?? "GET").toUpperCase()} ${url.split("?")[0].slice(0, 90)}`
            );
            const resp = await win.fetch(url, {
                method: String(req?.method ?? "GET").toUpperCase(),
                headers: req?.headers,
                body: req?.body,
            });
            const buf = await resp.arrayBuffer();
            const text = new TextDecoder().decode(buf);
            const headers: Record<string, string> = {};
            resp.headers.forEach((value: string, key: string) => {
                headers[key] = value;
            });
            let json: unknown = null;
            try {
                json = JSON.parse(text);
            } catch {
                json = null;
            }
            return { status: resp.status, headers, arrayBuffer: buf, text, json };
        } catch (err) {
            if (req?.throw === false) {
                return { status: 0, headers: {}, arrayBuffer: new ArrayBuffer(0), text: "", json: null };
            }
            throw err;
        }
    };
    win.requestUrl = sealedRequest;
    transportLog("[requesturl-shim] installed");
    return () => {
        if (win.requestUrl === sealedRequest) {
            win.requestUrl = original;
            win.__secureWebRequestUrlShimInstalled = false;
        }
    };
}

export function installSecureWebXhrShim(
    getSettings: () => SecureWebSettingsLike | undefined
): () => void {
    const win = (compatGlobal as any).window;
    if (!win || !win.XMLHttpRequest) return () => {};
    win.__secureWebXhrSealedInstalled = true;
    const OriginalXHR = win.__secureWebRawXHR ?? win.XMLHttpRequest;
    win.__secureWebRawXHR = OriginalXHR;
    transportLog(`[xhr-shim] installed (original=${typeof OriginalXHR})`);

    const matchesSealedRoute = (rawUrl: string): boolean => {
        try {
            const urlStr = String(rawUrl);
            // App resources must stay on the cheap startup path. Network
            // requests register the current configuration before matching:
            // XHR can be the first request after startup or a domain change.
            if (/^(https?|secureweb):\/\//i.test(urlStr)) {
                registerConfiguredGatewayHosts(getSettings());
            }
            // Cheapest gate FIRST: app-internal XHR (and everything that is
            // not gateway traffic) must never touch plugin state — a throw
            // or an expensive getter here lands on Obsidian's own startup
            // critical path.
            const looksGateway =
                urlStr.includes("/gateway/") ||
                urlStr.includes("/.well-known/") ||
                urlStr.includes("/transparency/") ||
                urlStr.includes("/healthz") ||
                urlStr.includes("/metrics") ||
                isRegisteredGatewayHost(urlStr);
            if (!looksGateway) {
                return false;
            }
            // Gateway infrastructure is NEVER sealed by the shim: the envelope
            // POST is already ciphertext, and if Obsidian's requestUrl is
            // XHR-backed, sealing it re-enters the sealed flow (infinite
            // recursion → renderer hangs at startup). Same rule as the
            // window.fetch interceptor.
            if (
                urlStr.includes("/gateway/e2e-envelope") ||
                urlStr.includes("/gateway/stream") ||
                urlStr.includes("/gateway/service-session") ||
                urlStr.includes("/.well-known/") ||
                urlStr.includes("/transparency/") ||
                urlStr.includes("/healthz") ||
                urlStr.includes("/metrics")
            ) {
                return false;
            }
            return (
                isRegisteredGatewayHost(urlStr)
            );
        } catch {
            // Fail open: never break the caller — worst case one request
            // rides unsealed and the gateway's blind mode answers 404.
            return false;
        }
    };

    const buildSecureFetch = (rawUrl: string) => {
        const settings = getSettings();
        let gatewayUrl = String(rawUrl).replace("secureweb:", "https:");
        try {
            gatewayUrl = new URL(gatewayUrl).origin;
        } catch {
            gatewayUrl = "https://localhost:8080";
        }
        // Everything deployment-specific comes from plugin configuration:
        // host from couchDB_URI, service identity from the setup link.
        let basePath: string | undefined;
        try {
            const configuredPath = settings?.couchDB_URI ? new URL(settings.couchDB_URI).pathname : "";
            if (configuredPath && configuredPath !== "/") {
                basePath = configuredPath.replace(/\/$/, "");
            }
        } catch {
            /* ignore malformed URI */
        }
        return createSecureWebFetch({
            gatewayUrl,
            serviceId: (settings as any)?.secureWebServiceId,
            targetHost: (settings as any)?.secureWebServiceId ? undefined : 'couchdb.local',
            basePath,
            passkeyToken: settings?.couchDB_PASSWORD,
        });
    };

    class SealedXHR extends OriginalXHR {
        private __sealed = false;
        private __method = "GET";
        private __url = "";
        private __headers: Record<string, string> = {};

        open(method: string, url: string | URL, ...rest: unknown[]) {
            const urlStr = String(url);
            const sealed = matchesSealedRoute(urlStr);
            transportLog(
                `[xhr-shim] open ${String(method).toUpperCase()} ${urlStr} -> ${sealed ? "SEAL" : "PASSTHROUGH"}`
            );
            if (sealed) {
                this.__sealed = true;
                this.__method = String(method).toUpperCase();
                this.__url = urlStr;
                this.__headers = {};
                return;
            }
            (super.open)(method, url, ...(rest));
        }

        setRequestHeader(key: string, value: string) {
            if (this.__sealed) {
                this.__headers[key] = value;
                return;
            }
            (super.setRequestHeader)(key, value);
        }

        send(body?: unknown) {
            if (!this.__sealed) {
                transportLog(`[xhr-shim] passthrough send ${this.__method}`);
                (super.send)(body);
                return;
            }
            const secureFetch = buildSecureFetch(this.__url);
            transportLog(`[xhr-shim] sealed send BEGIN ${this.__method} ${this.__url}`);
            void (async () => {
                try {
                    const res = await secureFetch(this.__url, {
                        method: this.__method,
                        headers: this.__headers,
                        body: body as BodyInit | undefined,
                    });
                    const text = await res.text();
                    transportLog(`[xhr-shim] sealed send OK ${res.status} ${this.__url}`);
                    const headerPairs: string[] = [];
                    res.headers.forEach((v, k) => headerPairs.push(`${k}: ${v}`));
                    Object.defineProperty(this, "status", { value: res.status, configurable: true });
                    Object.defineProperty(this, "statusText", {
                        value: res.statusText || "",
                        configurable: true,
                    });
                    Object.defineProperty(this, "readyState", { value: 4, configurable: true });
                    Object.defineProperty(this, "responseText", { value: text, configurable: true });
                    Object.defineProperty(this, "response", { value: text, configurable: true });
                    Object.defineProperty(this, "responseURL", {
                        value: this.__url,
                        configurable: true,
                    });
                    (this as any).getAllResponseHeaders = () => headerPairs.join("\r\n");
                    (this as any).getResponseHeader = (name: string) =>
                        res.headers.get(name) ?? null;
                    (this as any).onreadystatechange?.call(this, { target: this });
                    (this as any).onload?.call(this, { target: this });
                    (this as any).onloadend?.call(this, { target: this });
                    // PouchDB-style callers may listen via addEventListener
                    // instead of properties — fire real events too, or the
                    // request never completes and sync hangs.
                    if (typeof (this as any).dispatchEvent === "function" && typeof Event === "function") {
                        try {
                            this.dispatchEvent(new Event("readystatechange"));
                            this.dispatchEvent(new Event("load"));
                            this.dispatchEvent(new Event("loadend"));
                        } catch {
                            /* synthetic events unsupported — properties already fired */
                        }
                    }
                } catch (err) {
                    transportLog(
                        `[xhr-shim] sealed send FAIL ${this.__url}: ${err instanceof Error ? err.message : String(err)}`
                    );
                    (this as any).onerror?.call(this, err);
                    (this as any).onloadend?.call(this, err);
                    if (typeof (this as any).dispatchEvent === "function" && typeof Event === "function") {
                        try {
                            this.dispatchEvent(new Event("error"));
                            this.dispatchEvent(new Event("loadend"));
                        } catch {
                            /* ignore */
                        }
                    }
                }
            })();
        }

        abort() {
            if (this.__sealed) return;
            (super.abort)();
        }
    }

    win.XMLHttpRequest = SealedXHR;
    return () => {
        if (win.XMLHttpRequest === SealedXHR) {
            win.XMLHttpRequest = OriginalXHR;
            win.__secureWebXhrSealedInstalled = false;
        }
    };
}
