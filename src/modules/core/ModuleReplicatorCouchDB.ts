import { fireAndForget } from "octagonal-wheels/promises";
import { REMOTE_MINIO, REMOTE_P2P, type RemoteDBSettings } from "@vrtmrz/livesync-commonlib/compat/common/types";
import { LiveSyncCouchDBReplicator } from "@vrtmrz/livesync-commonlib/compat/replication/couchdb/LiveSyncReplicator";
import type { LiveSyncAbstractReplicator } from "@vrtmrz/livesync-commonlib/compat/replication/LiveSyncAbstractReplicator";
import { AbstractModule } from "@/modules/AbstractModule";
import type { LiveSyncCore } from "@/main";
import { createSecureWebFetch } from "@/secureweb/envelope";

export class ModuleReplicatorCouchDB extends AbstractModule {
    _anyNewReplicator(settingOverride: Partial<RemoteDBSettings> = {}): Promise<LiveSyncAbstractReplicator | false> {
        const settings = { ...this.settings, ...settingOverride };
        // If new remote types were added, add them here. Do not use `REMOTE_COUCHDB` directly for the safety valve.
        if (settings.remoteType == REMOTE_MINIO || settings.remoteType == REMOTE_P2P) {
            return Promise.resolve(false);
        }

        // Detect if the remote URI is targeted through the SecureWeb envelope plane
        const remoteUri = (settings.couchDB_URI || '').toLowerCase();
        if (remoteUri.includes('/gateway/e2e-envelope') || remoteUri.startsWith('secureweb:')) {
            const gatewayUrl = settings.couchDB_URI.replace('secureweb:', 'https:').replace('/gateway/e2e-envelope', '');
            const secureFetch = createSecureWebFetch({
                gatewayUrl: gatewayUrl || 'https://localhost:8080',
                targetHost: 'couchdb.local',
                passkeyToken: settings.couchDB_PASSWORD || undefined,
            });

            // Attach secure fetch interceptor to global window if running within Obsidian DOM context
            if (typeof window !== 'undefined') {
                const win = window as unknown as { __secureWebOriginalFetch?: typeof fetch };
                if (!win.__secureWebOriginalFetch) {
                    win.__secureWebOriginalFetch = window.fetch.bind(window);
                }
                const origFetch = win.__secureWebOriginalFetch;

                window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
                    const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
                    if (urlStr.includes('/gateway/e2e-envelope') || (gatewayUrl && urlStr.startsWith(gatewayUrl))) {
                        return secureFetch(input, init);
                    }
                    return origFetch(input, init);
                };
            }
        }

        return Promise.resolve(new LiveSyncCouchDBReplicator(this.core));
    }
    _everyAfterResumeProcess(): Promise<boolean> {
        if (this.services.appLifecycle.isSuspended()) return Promise.resolve(true);
        if (!this.services.appLifecycle.isReady()) return Promise.resolve(true);
        if (this.settings.remoteType != REMOTE_MINIO && this.settings.remoteType != REMOTE_P2P) {
            const LiveSyncEnabled = this.settings.liveSync;
            const continuous = LiveSyncEnabled;
            const eventualOnStart = !LiveSyncEnabled && this.settings.syncOnStart;
            // If enabled LiveSync or on start, open replication
            if (LiveSyncEnabled || eventualOnStart) {
                // And note that we do not open the conflict detection dialogue directly during this process.
                // This should be raised explicitly if needed.
                fireAndForget(async () => {
                    const canReplicate = await this.services.replication.isReplicationReady(false);
                    if (!canReplicate) return;
                    const openReplication = () =>
                        this.core.replicator.openReplication(this.settings, continuous, false, false);
                    if (continuous) {
                        void openReplication();
                    } else {
                        await this.services.replicator.runFiniteReplicationActivity(openReplication, {
                            label: "replication",
                        });
                    }
                });
            }
        }

        return Promise.resolve(true);
    }
    override onBindFunction(core: LiveSyncCore, services: typeof core.services): void {
        services.replicator.getNewReplicator.addHandler(this._anyNewReplicator.bind(this));
        services.appLifecycle.onResumed.addHandler(this._everyAfterResumeProcess.bind(this));
    }
}
