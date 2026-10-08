# SecureWeb transport for Self-hosted LiveSync

Last updated: 2026-10-05

The SecureWeb transport seals CouchDB requests in post-quantum X-Wing
(`X25519` + `ML-KEM-768`) envelopes before sending them through the gateway.
The gateway's CouchDB terminator opens the envelope and sends the request to
the configured backend. Encrypted replies use a fresh client reply key.
LiveSync's application-level encryption remains a separate setting.

## Install the SecureWeb build

The fork release `1.0.35-secureweb.1` is based on upstream 1.0.35. Download
`main.js`, `manifest.json`, and `styles.css` from the fork's GitHub Release,
and place all three in your Vault's `.obsidian/plugins/obsidian-livesync`
directory. Reload Obsidian, then enable Self-hosted LiveSync. The release is
marked as a pre-release; real Obsidian and live gateway acceptance remain
separate from the automated checks below.

## Configuration

Add or edit a CouchDB connection profile under **Connection settings** →
**Saved connections**. In the CouchDB Setup dialogue, enter:

| Setting | Value |
| --- | --- |
| **URL** (`couchDB_URI`) | `https://notes.example.com/gateway/e2e-envelope` |
| **Username** (`couchDB_USER`) | `secureweb` |
| **Password** (`couchDB_PASSWORD`) | The SecureWeb access token |
| **Database Name** (`couchDB_DBNAME`) | Your database name, such as `obsidian_vault` |

The gateway must publish its X-Wing key at
`/.well-known/gateway-pubkey`, permit the target host `couchdb.local`, and
have the corresponding terminator configured. The transport converts the
connection's Basic password into a Bearer token inside the encrypted envelope.
Neither the discovery request nor the outer envelope request carries that token.
The gateway deployment determines the backend's credentials and permissions.

Use **Test connection and save** for an existing profile. The onboarding
actions described in [Settings](settings.md#connection-and-save-actions)
can create a missing database only when that flow and the account permit it.
Enable the desired Sync Mode after the connection succeeds.

**Use Internal API** (`useRequestAPI`) selects Obsidian's native request adapter
for the discovery request and encrypted envelope POST. The default uses the
web-compatible adapter. Both paths seal CouchDB payloads. The native adapter
does not guarantee cancellation of an HTTP request already in flight.

## Upstream integration

The fork uses the upstream 1.0.35 Replicator provider and owned-resource
lifecycle. SecureWeb is attached to `ObsidianRemoteService`, the shared
CouchDB HTTP boundary, so replication, connection probes, Security Seed
preparation, and central administration use the same transport. Each request
uses its connection's credentials, including a profile being tested before
it becomes active. The public-key cache is separated by gateway origin.

Only `/gateway/e2e-envelope` and its descendant paths activate this transport.
The retained `secureweb://` URI spelling is normalised when opening a remote
connection; use the HTTPS URL above in the Setup dialogue. Ordinary CouchDB
URLs and Object Storage retain their upstream behaviour. No global `fetch`
function is replaced.

## Failure and verification

Discovery failure, a denied target host, a revoked key, or decryption failure
stops the encrypted request. There is no plaintext retry. Check the plug-in's
log and the gateway's discovery, host policy, and terminator configuration
before retrying. Use the recovery steps in [Troubleshooting](troubleshooting.md)
for local database or Vault problems.

At the public gateway boundary, CouchDB operations should appear as
`POST /gateway/e2e-envelope` with `application/octet-stream` bodies. The sealed
inner path retains the database path and query, such as
`/obsidian_vault/_changes?since=0`, without the envelope endpoint prefix.

The unit suite covers the TypeScript cryptographic round trip, Rust wire
fixtures, HTTP service composition, profile isolation, adapter selection,
and cancellation. Run `node --import tsx scripts/secureweb-http-interop-test.mjs`
for a local HTTP peer check using Commonlib's actual PouchDB connection. It
verifies sealed credentials, an encrypted reply, and owned connection closure.
A live gateway and real Obsidian synchronisation require separate deployment
testing.
