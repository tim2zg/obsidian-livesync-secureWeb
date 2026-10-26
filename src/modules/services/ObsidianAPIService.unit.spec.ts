import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
    requestUrl: vi.fn(),
    platform: {
        isMobile: false,
    },
}));

vi.mock("@/deps.ts", () => ({
    Platform: mocks.platform,
    requestUrl: mocks.requestUrl,
}));

vi.mock("@/deps", () => ({
    Platform: mocks.platform,
    requestUrl: mocks.requestUrl,
}));

vi.mock("@/modules/essentialObsidian/APILib/ObsHttpHandler", () => ({
    ObsHttpHandler: class {},
}));

vi.mock("./ObsidianConfirm", () => ({
    ObsidianConfirm: class {},
}));

import { registerGatewayHost } from "@/secureweb/envelope";
import { ObsidianAPIService } from "./ObsidianAPIService";
import type { ObsidianServiceContext } from "./ObsidianServiceContext";

function createService(workspace: Record<string, unknown>, isMobile = false): ObsidianAPIService {
    return new ObsidianAPIService({
        app: { workspace, isMobile },
    } as unknown as ObsidianServiceContext);
}

beforeEach(() => {
    mocks.platform.isMobile = false;
    vi.clearAllMocks();
});

describe("ObsidianAPIService.showWindowOnRight", () => {
    it("keeps the status view in the right leaf on mobile", async () => {
        mocks.platform.isMobile = true;
        const rightLeaf = {
            setViewState: vi.fn().mockResolvedValue(undefined),
        };
        const workspace = {
            getLeavesOfType: vi.fn(() => []),
            getLeaf: vi.fn(),
            getRightLeaf: vi.fn(() => rightLeaf),
            revealLeaf: vi.fn().mockResolvedValue(undefined),
        };
        const service = createService(workspace, true);

        expect(service.isMobile()).toBe(true);
        await service.showWindowOnRight("p2p-status");

        expect(workspace.getLeavesOfType).toHaveBeenCalledWith("p2p-status");
        expect(workspace.getRightLeaf).toHaveBeenCalledWith(false);
        expect(workspace.getLeaf).not.toHaveBeenCalled();
        expect(rightLeaf.setViewState).toHaveBeenCalledWith({
            type: "p2p-status",
            active: false,
        });
        expect(workspace.revealLeaf).toHaveBeenCalledWith(rightLeaf);
    });
});

afterEach(() => {
    vi.unstubAllGlobals();
});

describe("ObsidianAPIService.nativeFetch", () => {
    it("routes security-seed requests on a configured custom domain through the sealed fetch interceptor", async () => {
        registerGatewayHost("https://sync.example.test");
        const response = new Response(JSON.stringify({ _id: "sync-parameters" }), { status: 200 });
        const sealedFetch = vi.fn().mockResolvedValue(response);
        vi.stubGlobal("fetch", sealedFetch);
        const service = createService({});
        const url = "https://sync.example.test/study-notes/sync-parameters";
        const options = { headers: { Authorization: "Basic test-only" } };

        expect(await service.nativeFetch(url, options)).toBe(response);
        expect(sealedFetch).toHaveBeenCalledWith(url, options);
        expect(mocks.requestUrl).not.toHaveBeenCalled();
    });

    it("preserves Request bodies and request options on the web-compatible path", async () => {
        registerGatewayHost("https://sync.example.test");
        const response = new Response('{"ok":true}', { status: 201 });
        const sealedFetch = vi.fn().mockResolvedValue(response);
        vi.stubGlobal("fetch", sealedFetch);
        const request = new Request("https://sync.example.test/study-notes/sync-parameters", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: '{"_id":"sync-parameters"}',
        });
        const options = { signal: new AbortController().signal };
        const service = createService({});

        expect(await service.webCompatFetch(request, options)).toBe(response);
        expect(sealedFetch).toHaveBeenCalledWith(request, options);
        expect(await request.text()).toBe('{"_id":"sync-parameters"}');
        expect(mocks.requestUrl).not.toHaveBeenCalled();
    });

    it("propagates sealed transport failures without sending a plaintext fallback", async () => {
        registerGatewayHost("https://sync.example.test");
        const failure = new Error("service session rejected");
        vi.stubGlobal("fetch", vi.fn().mockRejectedValue(failure));

        await expect(createService({}).nativeFetch("https://sync.example.test/study-notes/sync-parameters"))
            .rejects.toBe(failure);
        expect(mocks.requestUrl).not.toHaveBeenCalled();
    });

    it("keeps ordinary CouchDB requests on Obsidian's native CORS-compatible transport", async () => {
        const bytes = new TextEncoder().encode('{"db_name":"notes"}');
        mocks.requestUrl.mockResolvedValue({ status: 200, headers: {}, arrayBuffer: bytes.buffer });
        const sealedFetch = vi.fn();
        vi.stubGlobal("fetch", sealedFetch);

        const response = await createService({}).nativeFetch("https://couchdb.example.test/notes");

        expect(await response.json()).toEqual({ db_name: "notes" });
        expect(mocks.requestUrl).toHaveBeenCalledOnce();
        expect(sealedFetch).not.toHaveBeenCalled();
    });
});
