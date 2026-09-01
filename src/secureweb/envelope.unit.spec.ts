import { describe, expect, it, vi } from 'vitest';
import { isHostAllowed, isKeyRevoked, createSecureWebFetch } from '@/secureweb/envelope';

describe('SecureWeb Envelope Transport', () => {
    it('verifies allowed hosts matching', () => {
        const allowed = ['couchdb.local', 'notes.example.com'];
        expect(isHostAllowed('couchdb.local', allowed)).toBe(true);
        expect(isHostAllowed('COUCHDB.LOCAL', allowed)).toBe(true);
        expect(isHostAllowed('sub.couchdb.local', allowed)).toBe(true);
        expect(isHostAllowed('other.local', allowed)).toBe(false);
        expect(isHostAllowed('attacker.com', allowed)).toBe(false);

        expect(isHostAllowed('anything.com', ['*'])).toBe(true);
    });

    it('verifies revoked key detection', () => {
        const revoked = ['revoked_key_123', 'REVOKED_HEX_ABC'];
        expect(isKeyRevoked('revoked_key_123', revoked)).toBe(true);
        expect(isKeyRevoked('REVOKED_KEY_123', revoked)).toBe(true);
        expect(isKeyRevoked('active_key_xyz', revoked)).toBe(false);
    });

    it('wraps fetch into envelope request structure', async () => {
        const mockFetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true })));
        global.fetch = mockFetch;

        const secureFetch = createSecureWebFetch({
            gatewayUrl: 'http://127.0.0.1:8080',
            targetHost: 'couchdb.local',
            passkeyToken: 'test-token',
        });

        const resp = await secureFetch('http://127.0.0.1:8080/vault1/_session', {
            method: 'GET',
        });

        expect(resp).toBeDefined();
        expect(mockFetch).toHaveBeenCalled();
    });
});
