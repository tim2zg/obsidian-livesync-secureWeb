# SecureWeb transport for Self-hosted LiveSync

The SecureWeb fork uses the two-layer V2 envelope protocol. The request is
sealed to the selected service, then wrapped in a routing envelope for the
gateway. Replies are sealed to a fresh client reply key. A V2-capable gateway
is required. V1 gateway-terminating envelopes are no longer supported.

## Configure a gateway

Use the SecureWeb setup link supplied by your operator. It configures the
gateway, database, device App Token, and service identifier together. The
operator can use a stable custom domain; no deployment hostname or credential
is embedded in the plug-in bundle.

For an explicitly configured connection, use a URI such as
`https://gateway.example.test/gateway/e2e-envelope`, or the retained
`secureweb://gateway.example.test` scheme. Each device needs its own App Token.
Ordinary CouchDB profiles continue to use the upstream transport.

App Token secrets are exchanged for bounded service sessions. The raw secret
is not used as the bearer credential inside service requests. Both native and
web-compatible requests, connection probes, and Security Seed reads use the
configured sealed transport. A failed session or encryption operation stops
the request without retrying the database request in plaintext.

## Large attachment reads

Large batches of on-demand Chunks can exceed a gateway response buffer even
when each document fits. The connector divides keyed `_all_docs` and
`_bulk_get` queries into batches of at most four documents, then restores the
original response order. A read which still returns a size-related error is
retried with smaller batches. Writes and paginated queries retain their
original behaviour. Concurrent large reads share a gateway queue.

For initial catch-up on a memory-constrained tablet, set **Batch size of
on-demand fetching** to `1` under **Advanced**. The minimum accepted value is
one. Keep Obsidian in the foreground until attachment downloads finish.

## Verification

Run `npm run test:secureweb` for the offline encrypted request/reply tests.
They cover desktop and mobile API paths, XHR and requestUrl probes, profile
credentials, gateway domain changes, request bodies, cancellation, and
authentication failures. The suite runs before `npm run build` and in its own
CI job. Run `npm run check` and `npm run test:unit` for the broader checks.

The tests use generated keys and synthetic credentials. Production deployment
details, device tokens, Vault settings, and diagnostic exports belong outside
the repository. A passing offline suite does not establish a physical-device
or operator-specific gateway deployment result.
