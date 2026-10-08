// Run from the repository root: node --import tsx scripts/secureweb-http-interop-test.mjs
// A local HTTP peer exercises Commonlib's actual PouchDB connection and
// encrypted transport without accessing a deployed gateway or Vault.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { ServiceContext } from "@vrtmrz/livesync-commonlib/context";
import { PouchDB } from "@vrtmrz/livesync-commonlib/compat/pouchdb/pouchdb-browser";
import { createNewVaultSettings } from "@vrtmrz/livesync-commonlib/settings";
import { reactiveSource } from "octagonal-wheels/dataobject/reactive";
import { SecureWebRemoteService } from "../src/secureweb/remote.ts";
import { generateKeypair } from "../src/secureweb/xwing.ts";
import { open, seal, GATEWAY_REQUEST_INFO, GATEWAY_RESPONSE_INFO } from "../src/secureweb/hpke.ts";
import { decodeKeyBytes, encodeBase64 } from "../src/secureweb/envelope.ts";
import {
    calculatePadLen, padBody, deserializeHybridSealed, deserializeGatewayEnvelope,
    serializeHybridSealed, serializeGatewayHttpResponse,
} from "../src/secureweb/codec.ts";

const keys = generateKeypair();
const envelopes = [];
const physicalPaths = [];
const failures = [];
const server = createServer(async (request, response) => {
    try {
        physicalPaths.push(request.url);
        assert.equal(request.headers.authorization, undefined);
        if (request.url === "/.well-known/gateway-pubkey") {
            response.setHeader("content-type", "application/json");
            response.end(JSON.stringify({ pubkey: encodeBase64(keys.publicKey), hosts: ["couchdb.local"], revoked: [] }));
            return;
        }
        assert.equal(request.url, "/gateway/e2e-envelope");
        assert.equal(request.method, "POST");
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const wire = deserializeHybridSealed(new Uint8Array(Buffer.concat(chunks)));
        const envelope = deserializeGatewayEnvelope(open(wire.kemOutput, wire.ciphertext, keys.secretKey, GATEWAY_REQUEST_INFO));
        envelopes.push(envelope);
        assert.equal(new Headers(envelope.headers).get("authorization"), "Bearer loopback:credential");
        assert.equal(envelope.targetHost, "couchdb.local");
        const replyKey = decodeKeyBytes(envelope.headers.find(([key]) => key === "x-reply-pubkey")[1]);
        const body = new TextEncoder().encode(JSON.stringify({ _id: "example", _rev: "1-fixture", verified: true }));
        const padLen = calculatePadLen(body.length);
        const plaintext = serializeGatewayHttpResponse({ status: 200, headers: [["content-type", "application/json"]], body: padBody(body, padLen), padLen });
        const encrypted = serializeHybridSealed(seal(replyKey, GATEWAY_RESPONSE_INFO, new Uint8Array(0), plaintext));
        response.setHeader("content-type", "application/octet-stream");
        response.end(encrypted);
    } catch (error) {
        failures.push(error);
        response.statusCode = 500;
        response.end("Loopback fixture failed");
    }
});

let connection;
try {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const { port } = server.address();
    const APIService = {
        isOnline: true,
        webCompatFetch: fetch,
        nativeFetch: fetch,
        addLog() {},
        requestCount: reactiveSource(0),
        responseCount: reactiveSource(0),
    };
    const remote = new SecureWebRemoteService(new ServiceContext(), {
        pouchDB: PouchDB, APIService,
        appLifecycle: { getUnresolvedMessages: { addHandler() {} } },
        setting: { currentSettings: createNewVaultSettings },
    });
    connection = await remote.connect(
        `http://127.0.0.1:${port}/gateway/e2e-envelope/vault`,
        { type: "basic", username: "secureweb", password: "loopback:credential" },
        false, false, false, false, true, false, {}, false, async () => new Uint8Array()
    );
    assert.notEqual(typeof connection, "string", typeof connection === "string" ? connection : undefined);
    const document = await connection.db.get("example");
    assert.equal(document.verified, true);
    assert.equal(envelopes.length, 1);
    assert.equal(envelopes[0].method, "GET");
    assert.equal(envelopes[0].pathAndQuery, "/vault/example");
    assert.deepEqual(physicalPaths, ["/.well-known/gateway-pubkey", "/gateway/e2e-envelope"]);
    await connection.close();
    await assert.rejects(() => connection.db.get("example"));
    assert.equal(physicalPaths.length, 2);
    assert.deepEqual(failures, []);
    console.log(JSON.stringify({ result: "passed", checks: ["PouchDB HTTP connection", "sealed credentials", "encrypted reply", "owned connection closure"], physicalRequests: physicalPaths.length }));
} finally {
    if (connection && typeof connection !== "string") await connection.close();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
}
