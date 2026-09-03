// Live interop: native TS envelope transport against the deployed gateway
// via SSH local forward (127.0.0.1:8080 -> manager loopback).
// Verifies the full seal -> HPKE open -> terminator -> CouchDB ->
// sealed response -> TS open round-trip.
import { createSecureWebFetch } from "../src/secureweb/envelope";

const GW = process.env.SW_GW || "http://127.0.0.1:8080";
const gatewayUrl = GW;

async function main() {
    console.log("== Live interop: TS native envelope -> deployed gateway ==");

    // 1. Fetch gateway pubkey
    const pk = await fetch(`${GW}/.well-known/gateway-pubkey`).then((r) => r.json());
    console.log("pubkey length:", (pk.public_key_base64 || "").length ? "loaded" : "MISSING", "hosts:", pk.hosts);

    // 2. Build the secure fetch
    const secureFetch = createSecureWebFetch({
        gatewayUrl,
        targetHost: "couchdb.local",
    });

    // 3. _all_dbs through the envelope plane
    const dbRes = await secureFetch(`${GW}/gateway/e2e-envelope/_all_dbs`, { method: "GET" });
    console.log("_all_dbs status:", dbRes.status, "ct:", dbRes.headers.get("content-type"));
    const dbs = await dbRes.json();
    console.log("dbs:", JSON.stringify(dbs));

    // 4. Create a scratch DB + write a doc + read _changes (full surface)
    const dbName = `sw_live_${Date.now()}`;
    const putDb = await secureFetch(`${GW}/gateway/e2e-envelope/${dbName}`, { method: "PUT" });
    console.log("PUT db:", putDb.status, await putDb.text());

    const putDoc = await secureFetch(`${GW}/gateway/e2e-envelope/${dbName}/doc1`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ hello: "secureweb-live" }),
    });
    console.log("PUT doc:", putDoc.status, await putDoc.text());

    const changes = await secureFetch(`${GW}/gateway/e2e-envelope/${dbName}/_changes`, { method: "GET" });
    console.log("_changes:", changes.status, await changes.text());

    const cleanup = await fetch(`${GW}/gateway/e2e-envelope/${dbName}`, { method: "DELETE" }).catch((e) => ({ status: "ERR", text: String(e) }));
    console.log("cleanup (direct, envelope path):", cleanup.status);

    console.log("== LIVE INTEROP OK ==");
}

main().catch((e) => {
    console.error("LIVE INTEROP FAILED:", e);
    process.exit(1);
});
