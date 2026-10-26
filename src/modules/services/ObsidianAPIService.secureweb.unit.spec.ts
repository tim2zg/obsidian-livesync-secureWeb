import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type ObsidianLiveSyncPlugin from "@/main";
import type { ObsidianServiceContext } from "./ObsidianServiceContext";
import { ObsidianAPIService } from "./ObsidianAPIService";
import { installGlobalSecureWebFetch } from "@/secureweb/globalFetch";
import {
    clearPubkeyCache,
    encodeBase64,
    installSecureWebRequestUrlShim,
    installSecureWebXhrShim,
    registerGatewayHost,
    setSecureWebSettingsProvider,
} from "@/secureweb/envelope";
import {
    deserializeHybridSealed,
    deserializeRouteEnvelope,
    deserializeServiceRequest,
    padToBucketFrame,
    serializeHybridSealed,
    serializeServiceResponse,
    SERVICE_ENVELOPE_VERSION,
    unpadFrame,
} from "@/secureweb/codec";
import { generateKeypair } from "@/secureweb/xwing";
import { open, seal, ROUTE_REQUEST_INFO, SERVICE_REQUEST_INFO, SERVICE_RESPONSE_INFO } from "@/secureweb/hpke";

const mocks = vi.hoisted(() => ({ requestUrl: vi.fn(), platform: { isMobile: false } }));
vi.mock("@/deps", () => ({ Platform: mocks.platform, requestUrl: mocks.requestUrl }));
vi.mock("@/deps.ts", () => ({ Platform: mocks.platform, requestUrl: mocks.requestUrl }));
import { ObsHttpHandler } from "@/modules/essentialObsidian/APILib/ObsHttpHandler";
import { HttpRequest } from "@smithy/protocol-http";
vi.mock("./ObsidianConfirm", () => ({ ObsidianConfirm: class {} }));

const seedPath = "/study-notes/_local/obsidian_livesync_sync_parameters";
const seed = { _id: "_local/obsidian_livesync_sync_parameters", version: 1, pbkdf2salt: "test-only-security-seed" };
const appSecret = "swt_v2_fixture_only_not_a_credential";

function createEnvironment(label: string, mobile = false) {
    const origin = `https://${label}.example.test`;
    const settings = {
        couchDB_URI: origin,
        couchDB_PASSWORD: appSecret,
        secureWebServiceId: "fixture-service",
        remoteConfigurations: {} as Record<string, { uri: string; isEncrypted: boolean }>,
    };
    const plugin = { core: { settings } } as unknown as ObsidianLiveSyncPlugin;
    const gateway = generateKeypair();
    const service = generateKeypair();
    const wireCalls: { origin: string; path: string; method: string }[] = [];
    const innerRequests: ReturnType<typeof deserializeServiceRequest>[] = [];
    let sessionStatus = 200;

    const wireFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
        wireCalls.push({ origin: url.origin, path: url.pathname, method: init?.method ?? "GET" });
        if (url.pathname === "/.well-known/gateway-pubkey") {
            return Response.json({
                pubkey: encodeBase64(gateway.publicKey), hosts: ["notes.local"], revoked: [],
                services: { "notes.local": { pubkey_base64: encodeBase64(service.publicKey), service_id: "fixture-service" } },
            });
        }
        if (url.pathname === "/gateway/service-session") {
            const body = JSON.parse(String(init?.body));
            expect(body.app_secret).toBe(appSecret);
            expect(body.service_id).toBe("fixture-service");
            return sessionStatus === 200
                ? Response.json({ access_token: "fixture-session", expires_in: 28800 })
                : Response.json({ error: "session rejected" }, { status: sessionStatus });
        }
        // Any request to a plaintext database path fails the test immediately.
        expect(url.pathname).toBe("/gateway/e2e-envelope");
        expect(init?.method).toBe("POST");
        const outer = deserializeHybridSealed(new Uint8Array(init?.body as ArrayBuffer));
        const route = deserializeRouteEnvelope(unpadFrame(open(outer.kemOutput, outer.ciphertext, gateway.secretKey, ROUTE_REQUEST_INFO)));
        expect(route.targetService).toBe("notes.local");
        const inner = deserializeHybridSealed(route.sealedRequest);
        const request = deserializeServiceRequest(unpadFrame(open(inner.kemOutput, inner.ciphertext, service.secretKey, SERVICE_REQUEST_INFO)));
        innerRequests.push(request);
        expect(request.headers).toContainEqual(["authorization", "Bearer fixture-session"]);
        const frame = padToBucketFrame(serializeServiceResponse({
            version: SERVICE_ENVELOPE_VERSION, status: request.method === "PUT" ? 201 : 200,
            headers: [["content-type", "application/json"]],
            body: new TextEncoder().encode(JSON.stringify(request.method === "PUT" ? { ok: true } : seed)),
        }));
        const response = serializeHybridSealed(seal(route.replyPubkey, SERVICE_RESPONSE_INFO, new Uint8Array(0), frame));
        return new Response(response as unknown as BodyInit, { headers: { "content-type": "application/octet-stream" } });
    });

    const requestUrl = vi.fn(async (param: { url: string; method?: string; body?: string | ArrayBuffer; headers?: Record<string, string> }) => {
        const response = await wireFetch(param.url, { method: param.method, body: param.body, headers: param.headers });
        const arrayBuffer = await response.arrayBuffer();
        const text = new TextDecoder().decode(arrayBuffer);
        const headers: Record<string, string> = {};
        response.headers.forEach((v, k) => { headers[k] = v; });
        let json: unknown;
        try { json = JSON.parse(text); } catch { json = null; }
        return { status: response.status, headers, arrayBuffer, text, json };
    });
    class PlainXHR extends EventTarget {
        open(_method: string, _url: string | URL) { throw new Error("Plaintext XHR must not reach the gateway"); }
        setRequestHeader(_key: string, _value: string) {}
        send(_body?: unknown) { throw new Error("Plaintext XHR must not reach the gateway"); }
        abort() {}
    }
    const win = { fetch: wireFetch as typeof fetch, requestUrl, XMLHttpRequest: PlainXHR };
    vi.stubGlobal("window", win);
    vi.stubGlobal("fetch", ((input, init) => win.fetch(input, init)) as typeof fetch);
    mocks.platform.isMobile = mobile;
    mocks.requestUrl.mockImplementation(requestUrl);
    setSecureWebSettingsProvider(() => settings);
    installGlobalSecureWebFetch(() => plugin);
    installSecureWebRequestUrlShim(() => plugin);
    installSecureWebXhrShim(() => settings);
    const API = new ObsidianAPIService({ app: { workspace: {}, isMobile: mobile } } as unknown as ObsidianServiceContext);
    return { origin, settings, API, wireCalls, innerRequests, win, rejectSession: () => { sessionStatus = 401; } };
}

beforeEach(() => {
    vi.clearAllMocks();
    clearPubkeyCache();
});
afterEach(() => {
    vi.unstubAllGlobals();
    setSecureWebSettingsProvider(() => undefined);
});

describe("SecureWeb runtime Security Seed regression", () => {
    it.each([false, true])("reads the existing seed through native and web-compatible transport (mobile=%s)", async (mobile) => {
        const env = createEnvironment(mobile ? "tablet" : "pc", mobile);
        expect(await (await env.API.nativeFetch(env.origin + seedPath)).json()).toEqual(seed);
        expect(await (await env.API.webCompatFetch(env.origin + seedPath)).json()).toEqual(seed);
        expect(env.innerRequests.map(r => r.pathAndQuery)).toEqual([seedPath, seedPath]);
        expect(env.wireCalls.filter(r => r.path === "/gateway/service-session")).toHaveLength(1);
    });

    it("uses the current custom domain after a gateway address change without a plug-in reload", async () => {
        const env = createEnvironment("previous-domain");
        await env.API.nativeFetch(env.origin + seedPath);
        env.settings.couchDB_URI = "https://replacement-domain.example.test";
        expect(await (await env.API.nativeFetch(env.settings.couchDB_URI + seedPath)).json()).toEqual(seed);
        expect(env.wireCalls[env.wireCalls.length - 1]?.origin).toBe(env.settings.couchDB_URI);
    });

    it("registers a plaintext remote profile before the flat settings are populated", async () => {
        const env = createEnvironment("profile-first");
        env.settings.couchDB_URI = "";
        env.settings.remoteConfigurations = { secureweb: { uri: `sls+${env.origin}/study-notes`, isEncrypted: false } };
        expect(await (await env.API.nativeFetch(env.origin + seedPath)).json()).toEqual(seed);
    });

    it("preserves an encoded database prefix, Request body, and query when sealing a seed update", async () => {
        const env = createEnvironment("prefix-and-body");
        env.settings.couchDB_URI += "/notes.local";
        const response = await env.API.webCompatFetch(new Request(env.settings.couchDB_URI + seedPath + "?rev=0-1", {
            method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(seed),
        }));
        expect(response.status).toBe(201);
        expect(env.innerRequests[0].pathAndQuery).toBe(seedPath + "?rev=0-1");
        expect(JSON.parse(new TextDecoder().decode(env.innerRequests[0].body))).toEqual(seed);
    });

    it("seals the direct requestUrl path used by tablet connection probes", async () => {
        const env = createEnvironment("tablet-requesturl", true);
        const response = await env.win.requestUrl({ url: env.origin + seedPath });
        expect(response.json).toEqual(seed);
        expect(env.innerRequests).toHaveLength(1);
    });

    it("seals imported native requestUrl calls from the tablet setup HTTP handler", async () => {
        const env = createEnvironment("tablet-imported-requesturl", true);
        const result = await new ObsHttpHandler().handle(new HttpRequest({
            protocol: "https:", hostname: new URL(env.origin).hostname,
            method: "GET", path: seedPath, headers: {},
        }));
        expect(result.response.statusCode).toBe(200);
        const reader = (result.response.body as ReadableStream<Uint8Array>).getReader();
        const chunk = await reader.read();
        expect(JSON.parse(new TextDecoder().decode(chunk.value))).toEqual(seed);
        expect(env.innerRequests).toHaveLength(1);
    });

    it("completes PouchDB XHR reads and writes through the sealed transport", async () => {
        const env = createEnvironment("tablet-xhr", true);
        const run = (method: string, body?: string) => new Promise<{ status: number; responseText: string }>((resolve, reject) => {
            const xhr = new env.win.XMLHttpRequest() as unknown as XMLHttpRequest;
            xhr.onload = () => resolve(xhr);
            xhr.onerror = () => reject(new Error("Sealed XHR failed"));
            xhr.open(method, env.origin + seedPath);
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.send(body);
        });
        expect(JSON.parse((await run("GET")).responseText)).toEqual(seed);
        expect((await run("PUT", JSON.stringify(seed))).status).toBe(201);
        expect(env.innerRequests.map(r => r.method)).toEqual(["GET", "PUT"]);
    });

    it("propagates a rejected session without sending a plaintext seed request", async () => {
        const env = createEnvironment("rejected-session");
        env.rejectSession();
        await expect(env.API.nativeFetch(env.origin + seedPath)).rejects.toThrow("HTTP 401");
        expect(env.innerRequests).toHaveLength(0);
        expect(env.wireCalls.every(r => r.path.startsWith("/.well-known/") || r.path === "/gateway/service-session")).toBe(true);
    });

    it("uses the request's profile credential when the active profile has a different token", async () => {
        const env = createEnvironment("draft-profile-credential");
        env.settings.couchDB_PASSWORD = "swt_v2_other_active_profile_fixture";
        const response = await env.API.nativeFetch(env.origin + seedPath, {
            headers: { authorization: `Basic ${btoa(`profile:${appSecret}`)}` },
        });
        expect(await response.json()).toEqual(seed);
    });

    it("preserves ordinary CouchDB fetching when SecureWeb is not configured", async () => {
        setSecureWebSettingsProvider(() => ({ couchDB_URI: "https://ordinary-couchdb.example.test" }));
        const native = vi.fn().mockResolvedValue({ status: 200, headers: {}, arrayBuffer: new TextEncoder().encode('{"ordinary":true}').buffer });
        mocks.requestUrl.mockImplementation(native);
        const fetch = vi.fn(); vi.stubGlobal("fetch", fetch);
        const API = new ObsidianAPIService({ app: { workspace: {} } } as unknown as ObsidianServiceContext);
        expect(await (await API.nativeFetch("https://ordinary-couchdb.example.test/vault")).json()).toEqual({ ordinary: true });
        expect(native).toHaveBeenCalledOnce();
        expect(fetch).not.toHaveBeenCalled();
    });

    it("does not recognise a gateway hostname inside another origin's query string", async () => {
        registerGatewayHost("https://trusted-gateway.example.test");
        const native = vi.fn().mockResolvedValue({ status: 200, headers: {}, arrayBuffer: new TextEncoder().encode('{}').buffer });
        mocks.requestUrl.mockImplementation(native);
        const fetch = vi.fn(); vi.stubGlobal("fetch", fetch);
        const API = new ObsidianAPIService({ app: { workspace: {} } } as unknown as ObsidianServiceContext);
        await API.nativeFetch("https://unrelated.example.test/?next=https://trusted-gateway.example.test");
        expect(native).toHaveBeenCalledOnce();
        expect(fetch).not.toHaveBeenCalled();
    });
});
