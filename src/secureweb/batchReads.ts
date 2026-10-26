/** Bound encrypted CouchDB query responses without changing write requests. */
const BATCH_DOCUMENTS = 4;
const gatewayReads = new Map<string, Promise<void>>();

function checkAbort(signal?: AbortSignal | null) {
    if (signal?.aborted) throw signal.reason ?? new DOMException("The request was aborted", "AbortError");
}

async function serialiseRead<T>(origin: string, signal: AbortSignal | null | undefined, task: () => Promise<T>): Promise<T> {
    const previous = gatewayReads.get(origin) ?? Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const tail = previous.then(() => gate);
    gatewayReads.set(origin, tail);
    try {
        await previous;
        checkAbort(signal);
        return await task();
    } finally {
        release();
        if (gatewayReads.get(origin) === tail) gatewayReads.delete(origin);
    }
}

/** LiveSync can ask for 100 multi-megabyte chunks in a single allDocs read.
 * Keep each sealed response small, preserve row order, and allow other tiny
 * reads (including replication checkpoints) to proceed independently. */
export function withBoundedCouchDBReads(fetchOne: typeof fetch): typeof fetch {
    return async (input, init) => {
        const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
        const endpoint = url.pathname.split("/").pop();
        if (endpoint !== "_all_docs" && endpoint !== "_bulk_get") return await fetchOne(input, init);
        const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
        if (method !== "POST" && !(method === "GET" && endpoint === "_all_docs")) return await fetchOne(input, init);
        let payload: Record<string, unknown>;
        try {
            if (method === "GET") {
                payload = { keys: JSON.parse(url.searchParams.get("keys") ?? "null") };
            } else {
                const body = init?.body ?? (input instanceof Request ? await input.clone().text() : undefined);
                const text = typeof body === "string" ? body : body instanceof ArrayBuffer ? new TextDecoder().decode(body)
                    : ArrayBuffer.isView(body) ? new TextDecoder().decode(body) : "";
                payload = JSON.parse(text) as Record<string, unknown>;
            }
        } catch { return await fetchOne(input, init); }
        if (!payload || typeof payload !== "object") return await fetchOne(input, init);
        const field = endpoint === "_all_docs" ? "keys" : "docs";
        const items = payload[field];
        if (!Array.isArray(items) || !items.length) return await fetchOne(input, init);
        // Pagination applies to the complete query, so leave those queries intact.
        if (["skip", "limit", "descending"].some(key => url.searchParams.has(key) || key in payload)) {
            return await fetchOne(input, init);
        }
        const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
        const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
        return await serialiseRead(url.origin, signal, async () => {
            const resultField = endpoint === "_all_docs" ? "rows" : "results";
            const read = async (part: unknown[]): Promise<Response> => {
                checkAbort(signal);
                const nextURL = new URL(url);
                let body: string | undefined;
                if (method === "GET") nextURL.searchParams.set("keys", JSON.stringify(part));
                else body = JSON.stringify({ ...payload, [field]: part });
                const response = await fetchOne(nextURL, { ...init, method, headers, signal, body });
                // These are read-only queries: retry a smaller query when one
                // batch still exceeds a gateway or upstream response limit.
                if (part.length > 1 && (response.status === 413 || response.status === 502)) {
                    await response.body?.cancel();
                    const middle = Math.ceil(part.length / 2);
                    return await merge([part.slice(0, middle), part.slice(middle)]);
                }
                return response;
            };
            const merge = async (parts: unknown[][]): Promise<Response> => {
                let first: Response | undefined;
                let combined: Record<string, unknown> | undefined;
                const rows: unknown[] = [];
                for (const part of parts) {
                    const response = await read(part);
                    if (!response.ok) return response;
                    const data = await response.json() as Record<string, unknown>;
                    if (!Array.isArray(data[resultField])) throw new Error("Invalid CouchDB batch read response");
                    first ??= response;
                    combined ??= data;
                    rows.push(...data[resultField]);
                }
                const responseHeaders = new Headers(first?.headers);
                for (const name of ["content-length", "content-encoding", "etag"]) responseHeaders.delete(name);
                responseHeaders.set("content-type", "application/json");
                return new Response(JSON.stringify({ ...combined, [resultField]: rows }), {
                    status: first?.status ?? 200, headers: responseHeaders,
                });
            };
            const parts: unknown[][] = [];
            for (let offset = 0; offset < items.length; offset += BATCH_DOCUMENTS) parts.push(items.slice(offset, offset + BATCH_DOCUMENTS));
            return await merge(parts);
        });
    };
}
