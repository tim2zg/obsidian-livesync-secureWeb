import { describe, expect, it, vi } from "vitest";
import { withBoundedCouchDBReads } from "./batchReads";

const origin = "https://bounded-reads.example.test";
function requestItems(input: RequestInfo | URL, init?: RequestInit): unknown[] {
    const url = new URL(input instanceof Request ? input.url : String(input));
    return init?.body ? Object.values(JSON.parse(String(init.body)))[0] as unknown[]
        : JSON.parse(url.searchParams.get("keys") ?? "[]") as unknown[];
}
function fixture(maximum = 4) {
    const calls: { url: string; init?: RequestInit; items: unknown[] }[] = [];
    const one = vi.fn<typeof fetch>(async (input, init) => {
        const url = input instanceof Request ? input.url : String(input);
        const items = requestItems(input, init);
        calls.push({ url, init, items });
        if (items.length > maximum) return Response.json({ error: "bad_gateway", reason: "failed to buffer module response" }, { status: 502 });
        return Response.json({ total_rows: 1000, offset: 0, update_seq: "fixture-seq",
            [url.includes("_bulk_get") ? "results" : "rows"]: items.map(item => ({ key: item, doc: { data: "fixture" } })),
        }, { headers: { etag: "stale-single-batch", "content-length": "123" } });
    });
    return { calls, one, fetch: withBoundedCouchDBReads(one) };
}
describe("bounded encrypted CouchDB reads", () => {
    it("downloads a 100-chunk query in bounded batches and preserves every row in order", async () => {
        const env = fixture(); const keys = Array.from({ length: 100 }, (_, n) => `chunk-${n}`);
        const response = await env.fetch(origin + "/vault/_all_docs?include_docs=true", {
            method: "POST", headers: { authorization: "Bearer fixture-session" }, body: JSON.stringify({ keys }),
        });
        const data = await response.json();
        expect(response.status).toBe(200);
        expect(data.rows.map((row: { key: string }) => row.key)).toEqual(keys);
        expect(data).toMatchObject({ total_rows: 1000, offset: 0, update_seq: "fixture-seq" });
        expect(env.calls).toHaveLength(25);
        expect(env.calls.every(call => call.items.length <= 4 && call.url.endsWith("?include_docs=true")
            && new Headers(call.init?.headers).get("authorization") === "Bearer fixture-session")).toBe(true);
        expect(response.headers.has("etag")).toBe(false);
        expect(response.headers.has("content-length")).toBe(false);
    });
    it("supports GET keys and bulk_get revision descriptors", async () => {
        const env = fixture(); const keys = ["a", "b", "b", "missing", "e"];
        const get = await env.fetch(origin + "/vault/_all_docs?include_docs=true&keys=" + encodeURIComponent(JSON.stringify(keys)));
        expect((await get.json()).rows.map((row: { key: string }) => row.key)).toEqual(keys);
        const docs = keys.map(id => ({ id, rev: "2-fixture" }));
        const bulk = await env.fetch(new Request(origin + "/vault/_bulk_get?revs=true", {
            method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ docs }),
        }));
        expect((await bulk.json()).results.map((row: { key: unknown }) => row.key)).toEqual(docs);
    });
    it("halves an oversized read and creates new requests until every response fits", async () => {
        const env = fixture(1); const keys = ["a", "b", "c", "d"];
        const response = await env.fetch(origin + "/vault/_all_docs", { method: "POST", body: JSON.stringify({ keys }) });
        expect((await response.json()).rows.map((row: { key: string }) => row.key)).toEqual(keys);
        expect(env.calls.map(call => call.items.length)).toEqual([4, 2, 1, 1, 2, 1, 1]);
    });
    it("propagates authentication errors and single-document failures without retrying", async () => {
        for (const status of [401, 403, 502]) {
            const one = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ error: "fixture" }, { status }));
            const fetch = withBoundedCouchDBReads(one);
            expect((await fetch(origin + "/vault/_all_docs", { method: "POST", body: JSON.stringify({ keys: ["one"] }) })).status).toBe(status);
            expect(one).toHaveBeenCalledOnce();
        }
    });
    it("leaves writes and pagination queries untouched", async () => {
        const one = vi.fn<typeof fetch>().mockImplementation(async () => Response.json({ ok: true }));
        const fetch = withBoundedCouchDBReads(one);
        for (const endpoint of ["_bulk_docs", "_all_docs?limit=2", "_all_docs?descending=true"]) {
            const options = { method: "POST", body: JSON.stringify({ keys: [1, 2, 3, 4, 5] }) };
            const url = origin + "/vault/" + endpoint;
            await fetch(url, options);
            expect(one).toHaveBeenLastCalledWith(url, options);
        }
    });
    it("stops subsequent batches when cancelled", async () => {
        const controller = new AbortController();
        const one = vi.fn<typeof fetch>().mockImplementation(async () => {
            controller.abort(); return Response.json({ rows: [] });
        });
        await expect(withBoundedCouchDBReads(one)(origin + "/vault/_all_docs", {
            method: "POST", signal: controller.signal, body: JSON.stringify({ keys: [1, 2, 3, 4, 5] }),
        })).rejects.toMatchObject({ name: "AbortError" });
        expect(one).toHaveBeenCalledOnce();
    });
    it("serialises large reads across transport instances for the same gateway", async () => {
        let active = 0; let peak = 0;
        const one: typeof fetch = async () => {
            active++; peak = Math.max(peak, active);
            await new Promise(resolve => setTimeout(resolve, 5)); active--;
            return Response.json({ rows: [] });
        };
        await Promise.all(Array.from({ length: 4 }, () => withBoundedCouchDBReads(one)(origin + "/vault/_all_docs", {
            method: "POST", body: JSON.stringify({ keys: [1, 2, 3, 4, 5] }),
        })));
        expect(peak).toBe(1);
    });
});
