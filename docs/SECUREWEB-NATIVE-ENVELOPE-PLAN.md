# SecureWeb LiveSync Fork — Native Envelope Transport Fix Plan

> Goal: make the plugin actually **run and sync** through the SecureWeb
> gateway — with **zero plaintext fallback** and **no WASM dependency**.
> The envelope (X-Wing HPKE seal/open + framing) is implemented natively
> in TypeScript using audited pure-JS crypto, then wired into PouchDB's
> real fetch path.
>
> Status: **PLAN** — not yet implemented. Wire contract below was verified
> against the SecureWeb source (commits `46ea643`/`894f2d6`, secure-core
> `hybrid.rs`/`gateway.rs`, common `lib.rs`, gateway `envelope.rs`).

---

## 0. Why native TS, not the WASM engine

The alternative is bundling `wasm-client/pkg` and exposing
`window.SecureWeb.WasmEngine`. Native TS wins for this plugin:

| | Native TS (@noble) | Bundled WASM engine |
|---|---|---|
| Load in Obsidian (Electron, file://, CSP) | nothing special — plain JS | wasm-bindgen init + binary embed; fragile under Obsidian's loader/CSP |
| Mobile (Capacitor) parity | works | needs same dance on mobile |
| main.js size | ~+200–400 kB | +wasm binary + glue (~1 MB+) |
| Crypto trust | audited noble + RFC 9180/X-Wing drafts | Rust/libcrux (stronger) |
| Risk | byte-exactness with Rust sealer | init/bundling risk |

The byte-exactness risk of native TS is **neutralised by the conformance
harness** (step 6): every seal/open in TS is checked against the real Rust
sealer via golden fixtures generated from the actual gateway keypair.
If conformance cannot be reached, fall back to the WASM path — but native
is the primary target.

---

## 1. The wire contract (verified against SecureWeb source)

### 1.1 Request — what the plugin must POST

```
outer:  POST {gatewayUrl}/gateway/e2e-envelope
        Content-Type: application/octet-stream
        body = bincode(HybridSealed)         (binary, NOT base64)

HybridSealed {                                // secure-core/src/hybrid.rs:58
  suite:      HybridSuite (enum, XWingDraft06 = 0, bincode varint)   // common serialise
  kem_output: Vec<u8>,    // X-Wing encap: 32B X25519 eph pk || 1088B ML-KEM-768 ct = 1120B
  ciphertext: Vec<u8>,    // AEAD out = plaintext + 16 (ChaCha20-Poly1305 tag)
}

plaintext sealed by HPKE = bincode(GatewayEnvelope)   // gateway.rs:129 seal
GatewayEnvelope {                                     // common/src/lib.rs:388
  version:           u8,           // 1
  sender_device_id:  String,
  target_host:       String,       // e.g. "couchdb.local"
  method:            String,       // upper-case
  path_and_query:    String,       // inner path ONLY (see §4 activation)
  headers:           Vec<(String,String)>,
  body:              Vec<u8>,      // raw body + pad_len zero bytes (see padding)
  nonce:             [u8;12],      // fresh random per request
  pad_len:           u16,
}
```

### 1.2 HPKE parameters (exact)

| Parameter | Value | Source |
|---|---|---|
| Mode | Base (RFC 9180) | hybrid.rs:100 |
| KEM | X-Wing draft-06 (X25519 + ML-KEM-768, hpke-rs `XWingDraft06`) | hybrid.rs:41 |
| KDF | HKDF-SHA-256 | hybrid.rs:102 |
| AEAD | ChaCha20-Poly1305 | hybrid.rs:103 |
| `info` (request) | `b"secureweb/gateway-e2e/v1:request"` | gateway.rs:41 |
| `info` (response) | `b"secureweb/gateway-e2e/v1:response"` | gateway.rs:42 |
| AAD | empty for both | gateway.rs:129/293 |

Gateway public key: fetch `GET {gatewayUrl}/.well-known/gateway-pubkey`
→ JSON `{ pubkey, public_key_base64, revoked?, hosts }`. The raw key is
**1216 bytes** = 32B X25519 pk ‖ 1184B ML-KEM-768 ek (verified live:
`gateway_pubkey_len=1216`).

### 1.3 Padding (size hiding, must match byte-for-byte)

- Buckets `PAD_BUCKETS = [1024, 4096, 16384]`; `PAD_OVERHEAD = 8`
  (common/src/lib.rs `PAD_OVERHEAD`, `pad_bucket_for`).
- `bucket = pad_bucket_for(raw_body_len)` = smallest bucket ≥
  `raw_len + PAD_OVERHEAD`, else round up to 16 KiB multiples.
- `pad_len = bucket − PAD_OVERHEAD − raw_len`; sealer appends that many
  zero bytes to `body` **before** bincode + HPKE seal.
- The gateway strips padding after open (`unpadded_body`).

### 1.4 Response — sealed back to a fresh reply key

Request header when response confidentiality is wanted:
`x-reply-pubkey: base64(STANDARD, raw X-Wing pk 1216B)`.

- Gateway replies `200`, `Content-Type: application/octet-stream`,
  `x-gateway-envelope: sealed-response`, body =
  `bincode(HybridSealed)` (envelope.rs:566–589).
- Inner plaintext (after HPKE open with the reply **secret**, same KEM/
  KDF/AEAD, `info = response`, aad empty) =
  `bincode(GatewayHttpResponse { status: u16, headers: Vec<(String,String)>,
  body: Vec<u8>, pad_len: u16 })` (gateway.rs:50). Headers are already
  whitelist-filtered by the gateway; body may carry trailing pad zeros
  when `pad_len > 0` — strip like §1.3.
- **Every request uses a fresh X-Wing reply keypair** (secret never
  leaves memory; nothing to persist). Cost: one ML-KEM keygen per
  request (~ms) — acceptable; can be per-session later.

### 1.5 bincode 1.3 layout (as produced by `bincode::serialize`)

Little-endian fixed-width integers; collection/string lengths as
**varint u64** prefixes. The conformance harness (step 6) is the arbiter —
do not hand-tune.

---

## 2. Dependency choice (pure-JS, audited, tiny)

- `@noble/curves` — X25519 (edwards/x25519) 
- `@noble/post-quantum` — ML-KEM-768 (noble's audited PQ impl) — or
  `@noble/post-quantum`'s ml-kem export
- `@noble/hashes` — SHA3-256 (X-Wing combiner) + HKDF already in noble
  (hkdf util) 
- WebCrypto `crypto.getRandomValues` for all randomness (no CSPRNG
  dependency)
- Implement: X-Wing composite KEM encap/decaps (X25519 ‖ ML-KEM with the
  draft-06 combiner, mirroring hpke-rs), HPKE RFC-9180 key schedule,
  bincode mini-codec, padding. **Do not import a full HPKE lib** — the
  surface here is small and a generic lib may not expose the X-Wing
  suite id this stack uses.

Checkpoint before building more: a 1-day spike that reproduces the X-Wing
combiner against a known-answer vector from `hpke-rs` (cargo registry
source on the build machine) — de-risks the single hardest part early.

---

## 3. Files in the fork

```
src/secureweb/
  codec.ts        NEW  bincode 1.3 encode/decode (varint LE), pad buckets
  xwing.ts        NEW  X-Wing keygen/encap/decaps on noble primitives
  hpke.ts         NEW  RFC 9180 base seal/open (HKDF-SHA256, ChaCha20-Poly1305)
  envelope.ts     REWRITE  createSecureWebFetch: seal request, open response,
                          build a real Response for PouchDB; NO plaintext fallback
  envelope.unit.spec.ts  EXTEND (codec/padding round-trips; fixture vectors)
src/modules/core/ModuleReplicatorCouchDB.ts   ACTIVATION (see §4)
docs/secureweb_transport.md  UPDATE (config below)
package.json      + @noble deps
```

`envelope.ts` changes of note: **delete the existing `catch → return
fetch(input)` plaintext fallback** (lines ~215–217) and the revoked-key
plaintext fallback — any failure must surface as a loud error, never a
cleartext request (operator requirement).

---

## 4. Activation — where PouchDB's fetch really happens

Facts verified in the fork today:
- `ModuleReplicatorCouchDB._anyNewReplicator` detects
  `/gateway/e2e-envelope` or `secureweb:` in `couchDB_URI` and stashes
  `createSecureWebFetch(...)` on `window.__secureWebPouchFetch` — but
  **no code ever reads that global**, and the returned
  `LiveSyncCouchDBReplicator` never receives the custom fetch.
- The commonlib (`@vrtmrz/livesync-commonlib`, a dependency) owns the
  PouchDB construction, so we cannot add an `opts.fetch` there without
  patching the package.

Activation plan (pick by spike result, in order of preference):

1. **Global fetch wrapper (preferred, zero commonlib changes).** At
   module bind time, wrap `window.fetch` with a shim: if the request URL
   begins with the configured envelope base (scheme://host/
   `/gateway/e2e-envelope…`), route it through the seal/open fetch;
   everything else passes through untouched. This mirrors the gateway's
   own Lane-B `upgrade.js` fetch-hijack (proven pattern), is active for
   every PouchDB call regardless of how commonlib builds its client, and
   can be torn down on module unload. Incoming URL rule: strip the
   `/gateway/e2e-envelope` prefix from the path → that remainder is the
   sealed inner `path_and_query`; `target_host` from config (default
   `couchdb.local`).
2. If PouchDB in the Obsidian runtime turns out to use XHR (not fetch)
   for the http adapter: set `settings.useCustomRequestHandler = true`
   and patch the commonlib replicator to pass
   `{ fetch: secureFetch }` in its PouchDB options (fork the package's
   built output in `node_modules` is unacceptable for a committed repo —
   use a proper source-level patch of the dependency via the fork's
   existing vendor story, or add the fetch at the PouchDB constructor the
   module already controls).

Spike deliverable: instrument once (temporary console.log in the fetch
wrapper), start a sync, and confirm **every** HTTP call to the remote
CouchDB base transits the wrapper (log method + path). Then remove the
log.

---

## 5. Runtime flow (target)

```
LiveSync replicator wants  GET https://gw.example.com/gateway/e2e-envelope/obsidian-livesync/_changes?…
  ↓ fetch wrapper matches envelope base
1. path_and_query = /obsidian-livesync/_changes?…     (prefix stripped)
2. plaintext = bincode(GatewayEnvelope{...})           (pad applied)
3. sealed = HPKE.seal(plaintext, gateway_pk, request-info)
4. body = bincode(HybridSealed{suite,kem_output,ciphertext})
5. reply_kp = xwing.keygen();  headers += x-reply-pubkey: b64(reply_pk)
6. POST {gatewayUrl}/gateway/e2e-envelope  ← the ONLY network call
7. resp: 200 octet-stream sealed-response → bincode → HPKE.open(reply_sk,
   response-info) → bincode(GatewayHttpResponse) → strip pad
8. return new Response(unpadded_body, {status, headers})   // PouchDB sees a normal response
```

`_session`, `_all_docs`, `_changes`, `_bulk_docs`, `_revs_diff`, doc
GET/PUT/DELETE, `_compact` all flow through the same path — PouchDB never
sees a difference.

Config surface (keep it minimal, in the existing LiveSync settings):

| Setting | Value | Notes |
|---|---|---|
| Remote type | CouchDB | unchanged |
| URI | `https://<tunnel-host>/gateway/e2e-envelope` | triggers envelope mode (existing detection) |
| DB name | as today | appended by PouchDB, stripped by wrapper |
| Username/Password | optional, forwarded inside envelope as `authorization` | terminator re-auths upstream itself |
| Target host | `couchdb.local` (default) | advanced: gateway terminator host |

---

## 6. Conformance & tests (the gate — no live test until green)

1. **Unit (fork, `npm run tsc-check` + vitest):**
   - codec round-trips for GatewayEnvelope/HybridSealed/GatewayHttpResponse
     vs golden bytes captured from the Rust side.
   - padding: exact pad_len/bucket tables (incl. oversize rounding).
   - X-Wing encap/decaps round-trip; HPKE seal/open round-trip (local keys).
2. **Golden fixtures (generate once from the REAL sealer):** a small
   throwaway Rust test in the secureWeb workspace (not committed to the
   fork) writes fixtures to JSON:
   - `seal_request`: rust seals a known GatewayEnvelope to the REAL
     gateway pubkey (from `gateway-hpke.json`), store bincode bytes.
     Fork test: TS **opens** with the gateway secret (fixture-only) and
     asserts plaintext == the known envelope (validates bincode+padding+
     HPKE open).
   - `seal_response`: rust seals a GatewayHttpResponse to a known reply
     pk; TS opens with the reply sk.
   - TS **seal** direction is validated in (3) against the live gateway —
     no deterministic coins in hpke-rs, so byte-golden of a fresh seal is
     impossible; live interop is the correct proof.
3. **Live interop (must pass before any user config):**
   - Local: run the release `secure-gateway` on loopback (Windows build
     exists), point the wrapper at it, run the fork's sync against a
     scratch CouchDB db via the terminator — full `_changes`/`_bulk_docs`
     round-trip through native envelopes.
   - Deployed: repeat against the manager gateway (10.0.6.33) through an
     SSH local forward to `127.0.0.1:8080` — proves the exact binary the
     vault will talk to. Check gateway log shows envelope opens and the
     security engine sees no plaintext.
4. **Negative tests:** sealed request to a revoked key → hard error, no
   network call; garbage pubkey → error; gateway unreachable → sync error
   state shown to user (never silent plaintext retry).

---

## 7. Build & ship (fork)

- `npm run build` (esbuild production) — noble deps bundle into main.js.
- Unit: `npm run tsc-check` + vitest green.
- Ship: `main.js` + `manifest.json` + `styles.css` into the vault's
  `.obsidian/plugins/obsidian-livesync/`.
- Enable the plugin, configure per §5 (URI must contain
  `/gateway/e2e-envelope`), enable LiveSync, watch the sync console:
  every request logged as envelope (wrapper log) and the vault's DB
  appears in `_all_dbs` on CouchDB through the terminator.

---

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| X-Wing combiner mismatch (draft-06 subtleties) | 1-day known-answer spike against hpke-rs before full build; conformance (6.2/6.3) as gate |
| bincode layout drift | golden fixtures pinned in unit tests; codec isolated in one file |
| PouchDB uses XHR not fetch in Obsidian | activation spike (step 4) decides; option 2 patched properly |
| ML-KEM keygen per request too slow on mobile | measure; if >50 ms, cache a reply keypair per sync session (still never reused across sessions) |
| Response > 2 MB buffer | LiveSync chunks writes; verify _bulk_docs sizes stay under gateway's 2 MiB buffered-response ceiling |
| Nobody can sync until this ships | it is the critical path; server side is verified and waiting |

---

## 9. Definition of done

1. `npm run tsc-check` + vitest green incl. golden fixtures.
2. Live interop green: local loopback gateway + scratch DB, full
   LiveSync replication round-trip (two-way, multiple docs, a delete).
3. Same against the deployed manager gateway via SSH forward; gateway log
   shows envelope opens, **no plaintext** entries; CouchDB `_all_dbs`
   shows the vault DB.
4. Plugin installed in the real vault, LiveSync syncs both directions
   through the envelope plane; kill the tunnel → clean sync error (no
   plaintext fallback, no crash loop).
5. Docs updated (`docs/secureweb_transport.md`, this plan marked DONE).
