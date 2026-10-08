import { beforeEach, describe, expect, it, vi } from "vitest";
import { ServiceContext } from "@vrtmrz/livesync-commonlib/context";
import { InjectableRemoteService } from "@vrtmrz/livesync-commonlib/compat/services/implements/injectable/InjectableRemoteService";
import { reactiveSource } from "octagonal-wheels/dataobject/reactive";
import { ObsidianRemoteService } from "@/modules/services/ObsidianServices";
import {
    calculatePadLen, deserializeGatewayEnvelope, deserializeHybridSealed, padBody,
    serializeGatewayHttpResponse, serializeHybridSealed, unpadBody, type GatewayEnvelope,
} from "@/secureweb/codec";
import { clearPubkeyCache, decodeKeyBytes, encodeBase64, SecureWebEnvelopeError } from "@/secureweb/envelope";
import { open, seal, GATEWAY_REQUEST_INFO, GATEWAY_RESPONSE_INFO } from "@/secureweb/hpke";
import { generateKeypair } from "@/secureweb/xwing";

function fixture(networkFetch: typeof fetch) {
    const webCompatFetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => networkFetch(input, init));
    const nativeFetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => networkFetch(input, init));
    const dependencies = {
        pouchDB: class {},
        APIService: {
            webCompatFetch, nativeFetch, addLog: vi.fn(),
            requestCount: reactiveSource(0), responseCount: reactiveSource(0),
        },
        appLifecycle: { getUnresolvedMessages: { addHandler: vi.fn() } },
        setting: {},
    } as unknown as ConstructorParameters<typeof InjectableRemoteService>[1];
    const service = new ObsidianRemoteService(new ServiceContext() as never, dependencies);
    return { service, webCompatFetch, nativeFetch };
}

function gateway() {
    const keys = generateKeypair();
    const opened: GatewayEnvelope[] = [];
    const networkFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/.well-known/gateway-pubkey")) {
            expect(new Headers(init?.headers).has("authorization")).toBe(false);
            return Response.json({ pubkey: encodeBase64(keys.publicKey), hosts: ["couchdb.local"], revoked: [] });
        }
        expect(url).toMatch(/^https:\/\/[^/]+\/gateway\/e2e-envelope$/);
        expect(init?.method).toBe("POST");
        expect(new Headers(init?.headers).has("authorization")).toBe(false);
        const wire = deserializeHybridSealed(new Uint8Array(init?.body as ArrayBuffer));
        const envelope = deserializeGatewayEnvelope(open(wire.kemOutput, wire.ciphertext, keys.secretKey, GATEWAY_REQUEST_INFO));
        opened.push(envelope);
        const replyKey = decodeKeyBytes(envelope.headers.find(([key]) => key === "x-reply-pubkey")![1]);
        const body = new TextEncoder().encode('{"ok":true}');
        const padLen = calculatePadLen(body.length);
        const response = serializeGatewayHttpResponse({ status: 201, headers: [["content-type", "application/json"]], body: padBody(body, padLen), padLen });
        const sealed = serializeHybridSealed(seal(replyKey, GATEWAY_RESPONSE_INFO, new Uint8Array(0), response));
        return new Response(sealed as unknown as BodyInit, { headers: { "content-type": "application/octet-stream" } });
    });
    return { opened, networkFetch };
}

describe("SecureWeb CouchDB HTTP service composition", () => {
    beforeEach(() => { clearPubkeyCache(); vi.restoreAllMocks(); });

    it.each([0, 1] as const)("seals Request bodies and connection credentials through adapter %s", async (adapter) => {
        const remote = gateway();
        const { service, webCompatFetch, nativeFetch } = fixture(remote.networkFetch);
        const controller = new AbortController();
        const request = new Request("https://gateway.test/gateway/e2e-envelope/vault/_bulk_docs?new_edits=false", {
            method: "POST", body: '{"docs":[]}',
            headers: { authorization: `Basic ${btoa("secureweb:profile:token")}`, "content-type": "application/json" },
        });
        const response = await service.performFetch(request, { signal: controller.signal }, adapter);
        expect(response.status).toBe(201);
        expect(await response.json()).toEqual({ ok: true });
        expect(service.hadLastPostFailedBySize).toBe(false);
        const envelope = remote.opened[0];
        expect(envelope.pathAndQuery).toBe("/vault/_bulk_docs?new_edits=false");
        expect(envelope.method).toBe("POST");
        expect(envelope.senderDeviceId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
        expect(new Headers(envelope.headers).get("authorization")).toBe("Bearer profile:token");
        expect(new TextDecoder().decode(unpadBody(envelope.body, envelope.padLen))).toBe('{"docs":[]}');
        expect(remote.networkFetch.mock.calls.every(([, init]) => init?.signal === controller.signal)).toBe(true);
        expect(adapter === 1 ? webCompatFetch : nativeFetch).not.toHaveBeenCalled();
        expect(adapter === 1 ? nativeFetch : webCompatFetch).toHaveBeenCalledTimes(2);
    });

    it("retains each profile's credentials and public key when probes use different gateways", async () => {
        const first = gateway();
        const second = gateway();
        const networkFetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
            String(input).startsWith("https://first.test/") ? first.networkFetch(input, init) : second.networkFetch(input, init)
        );
        const { service } = fixture(networkFetch);
        await Promise.all(["first", "second"].map((name) => service.performFetch(
            `https://${name}.test/gateway/e2e-envelope/vault`,
            { headers: { authorization: `Basic ${btoa(`secureweb:${name}-token`)}` } }
        )));
        await service.performFetch("https://first.test/gateway/e2e-envelope/vault");
        expect(first.opened).toHaveLength(2);
        expect(second.opened).toHaveLength(1);
        expect(new Headers(first.opened[0].headers).get("authorization")).toBe("Bearer first-token");
        expect(new Headers(second.opened[0].headers).get("authorization")).toBe("Bearer second-token");
        expect(first.networkFetch).toHaveBeenCalledTimes(3);
        expect(second.networkFetch).toHaveBeenCalledTimes(2);
    });

    it.each([
        "https://plain.test/vault/_changes", "https://plain.test:8080/vault",
        "https://example.trycloudflare.com/vault", "https://plain.test/gateway/e2e-envelope-other/vault",
        "https://plain.test/vault?next=/gateway/e2e-envelope",
    ])("retains upstream fetching for %s", async (url) => {
        const networkFetch = vi.fn(async () => Response.json({ plain: true }));
        const { service, webCompatFetch } = fixture(networkFetch);
        const opts = { method: "GET", headers: { authorization: "Bearer ordinary-token" } };
        expect(await (await service.performFetch(url, opts)).json()).toEqual({ plain: true });
        expect(webCompatFetch).toHaveBeenCalledExactlyOnceWith(url, opts);
    });

    it("fails without a plaintext retry when discovery fails", async () => {
        const networkFetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(null, { status: 503 }));
        const { service } = fixture(networkFetch);
        await expect(service.performFetch("https://gateway.test/gateway/e2e-envelope/vault")).rejects.toThrow(SecureWebEnvelopeError);
        expect(networkFetch).toHaveBeenCalledTimes(1);
        expect(networkFetch.mock.calls[0][0]).toBe("https://gateway.test/.well-known/gateway-pubkey");
    });

    it("makes no network request after connection cancellation", async () => {
        const networkFetch = vi.fn(async () => new Response());
        const { service } = fixture(networkFetch);
        const controller = new AbortController();
        controller.abort();
        // Older mobile engines have AbortController without these newer helpers.
        Object.defineProperties(controller.signal, {
            throwIfAborted: { value: undefined },
            reason: { value: undefined },
        });
        await expect(service.performFetch("https://gateway.test/gateway/e2e-envelope/vault", { signal: controller.signal })).rejects.toMatchObject({ name: "AbortError" });
        expect(networkFetch).not.toHaveBeenCalled();
    });

    it("normalises the retained secureweb scheme before upstream opens a connection", async () => {
        const connect = vi.spyOn(InjectableRemoteService.prototype, "connect").mockResolvedValue("fixture");
        const { service } = fixture(vi.fn());
        const args = ["secureweb://gateway.test/vault", { type: "basic", username: "secureweb", password: "token" }, false, false, false, false, true, false, {}, false, async () => new Uint8Array()] as Parameters<InjectableRemoteService<ServiceContext>["connect"]>;
        await service.connect(...args);
        expect(connect).toHaveBeenCalledExactlyOnceWith("https://gateway.test/gateway/e2e-envelope/vault", ...args.slice(1));
    });
});
