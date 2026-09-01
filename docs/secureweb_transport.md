# SecureWeb Transport for Self-Hosted LiveSync

> This document describes how the Self-Hosted LiveSync plug-in communicates through the SecureWeb privacy-preserving routing fabric.

---

## 1. Overview

The **SecureWeb Transport** allows Obsidian vaults to synchronise notes with an internal CouchDB backend without exposing unencrypted document payloads or database credentials to intermediate reverse proxies, public networks, or the Cloudflare edge.

```
┌───────────────────────────────┐
│ Obsidian LiveSync (Plug-in)   │
│ - Note Chunking & Metadata    │
│ - E2EE Payload Envelope Seal  │
└───────────────┬───────────────┘
                │  POST /gateway/e2e-envelope (HybridSealed)
                ▼
┌───────────────────────────────┐
│ SecureWeb Gateway (Loopback)  │
│ - Zero-Knowledge Router       │
│ - Replay Nonce Verification   │
│ - In-RAM Credential Injection │
└───────────────┬───────────────┘
                │  HTTP /api/sync/couchdb/... (Basic Auth)
                ▼
┌───────────────────────────────┐
│ CouchDB Backend (Debian LXC)  │
│ 10.0.6.170:5984               │
└───────────────────────────────┘
```

---

## 2. Key Features

- **Double-Layered Cryptography**: Note chunks are protected by LiveSync end-to-end encryption at the application level and encapsulated inside Post-Quantum X-Wing (`X25519` + `ML-KEM-768`) hybrid sealed envelopes on the transport plane.
- **In-RAM Credential Isolation**: CouchDB administrative passwords never leave the gateway memory. The plug-in authenticates using session tokens (such as Biometric Passkeys), preventing database credentials from being stored on client devices.
- **Transparent Fallback**: Should cryptographic envelope initialisation fail, the plug-in gracefully falls back to standard HTTPS communication without disrupting note editing.

---

## 3. Configuration

To connect the LiveSync plug-in through SecureWeb:

1. Open **LiveSync Settings** $\rightarrow$ **Remote Database Configuration**.
2. Select **CouchDB** as the remote database type.
3. Configure the **CouchDB Server URL**:
   ```
   https://notes.example.com/gateway/e2e-envelope
   ```
4. Configure your **Database Name** (for example: `obsidian_vault`).
5. Enter your SecureWeb access token in the **Password / Token** field.
6. Enable **Synchronise on start** or **LiveSync** to begin real-time synchronisation.

---

## 4. Verification

To verify that synchronisation is operating through the zero-knowledge envelope plane:
- Check the **Gateway Status Dashboard** at `https://gateway.example.com/status`.
- Inspect the **Connections & Lanes** tab:
  - **Lane A (Private Mode E2EE)** will increment with each replicated revision.
  - The **Obsidian LiveSync CouchDB Terminator** card will show active in-memory routing to `10.0.6.170:5984`.
