import { useP2PSettingsPreparation } from "@/serviceFeatures/useP2PSettingsPreparation";
import { LOG_LEVEL_URGENT } from "octagonal-wheels/common/logger";
import { getLanguage, Notice, Plugin, type App, type PluginManifest } from "./deps";
import { setGetLanguage } from "@vrtmrz/livesync-commonlib/compat/common/coreEnvFunctions";
setGetLanguage(getLanguage);
import { LiveSyncCommands } from "./features/LiveSyncCommands.ts";
import { HiddenFileSync } from "./features/HiddenFileSync/CmdHiddenFileSync.ts";
import { ConfigSync } from "./features/ConfigSync/CmdConfigSync.ts";
// import { ModuleDev } from "./modules/extras/ModuleDev.ts";

import { ModuleLog } from "./modules/features/ModuleLog.ts";
import { ModuleObsidianEvents } from "./modules/essentialObsidian/ModuleObsidianEvents.ts";
import { ModuleObsidianSettingDialogue } from "./modules/features/ModuleObsidianSettingTab.ts";
import { ModuleObsidianDocumentHistory } from "./modules/features/ModuleObsidianDocumentHistory.ts";
import { ModuleObsidianGlobalHistory } from "./modules/features/ModuleGlobalHistory.ts";
import { LocalDatabaseMaintenance } from "./features/LocalDatabaseMainte/CmdLocalDatabaseMainte.ts";
import type { InjectableServiceHub } from "@vrtmrz/livesync-commonlib/compat/services/implements/injectable/InjectableServiceHub";
import { ObsidianServiceHub } from "./modules/services/ObsidianServiceHub.ts";
import { ServiceRebuilder } from "@vrtmrz/livesync-commonlib/compat/serviceModules/Rebuilder";
import { ServiceDatabaseFileAccess } from "@/serviceModules/DatabaseFileAccess.ts";
import { ServiceFileAccessObsidian } from "@/serviceModules/ServiceFileAccessImpl.ts";
import { StorageAccessManager } from "@vrtmrz/livesync-commonlib/compat/managers/StorageProcessingManager";
import { ServiceFileHandler } from "./serviceModules/FileHandler.ts";
import { FileAccessObsidian } from "./serviceModules/FileAccessObsidian.ts";
import { StorageEventManagerObsidian } from "./managers/StorageEventManagerObsidian.ts";
import type { ServiceModules } from "./types.ts";
import { setNoticeClass } from "@vrtmrz/livesync-commonlib/compat/mock_and_interop/wrapper";
import type { ObsidianServiceContext } from "@/modules/services/ObsidianServiceContext";
import { LiveSyncBaseCore } from "./LiveSyncBaseCore.ts";
import { ModuleObsidianSettingsAsMarkdown } from "./modules/features/ModuleObsidianSettingAsMarkdown.ts";
import { SetupManager } from "./modules/features/SetupManager.ts";
import { enableI18nFeature } from "./serviceFeatures/onLayoutReady/enablei18n.ts";
import { useOfflineScanner } from "@vrtmrz/livesync-commonlib/compat/serviceFeatures/offlineScanner";
import { useRemoteConfiguration } from "@vrtmrz/livesync-commonlib/compat/serviceFeatures/remoteConfig";
import { useCheckRemoteSize } from "@vrtmrz/livesync-commonlib/compat/serviceFeatures/checkRemoteSize";
import { useRedFlagFeatures } from "./serviceFeatures/redFlag.ts";
import { useSetupProtocolFeature } from "./serviceFeatures/setupObsidian/setupProtocol.ts";
import { useSetupQRCodeFeature } from "@/serviceFeatures/setupObsidian/qrCode";
import { useSetupURIFeature } from "@/serviceFeatures/setupObsidian/setupUri";
import {
    showOnboardingInvitation,
    useSetupManagerHandlersFeature,
} from "./serviceFeatures/setupObsidian/setupManagerHandlers.ts";
import { useP2PReplicatorCommands, useP2PReplicatorFeature } from "@vrtmrz/livesync-commonlib/p2p";
import { useP2PReplicatorUI } from "./serviceFeatures/useP2PReplicatorUI.ts";
import { useReviewHarness } from "./serviceFeatures/useReviewHarness.ts";
import { createOpenReplicationUI, createOpenRebuildUI } from "./features/P2PSync/P2PReplicator/P2PReplicationUI.ts";
import { useCompatibilityReview } from "./serviceFeatures/compatibilityReview.ts";
import { createObsidianCompatibilityReviewUi } from "./serviceFeatures/compatibilityReviewObsidian.ts";
import { createFileReflectionProvenance } from "./serviceModules/FileReflectionProvenance.ts";
import { useInteractiveConflictResolutionFeature } from "./serviceFeatures/interactiveConflictResolution";
import { ConflictResolveModal } from "./modules/features/InteractiveConflictResolving/ConflictResolveModal.ts";
import { useObsidianReplicationRibbonFeature } from "./serviceFeatures/obsidianReplicationRibbon.ts";
import { useStartupLifecycleFeature } from "./serviceFeatures/startupLifecycle";
import { useJoinedDevicesFeature } from "./serviceFeatures/useJoinedDevices";
import { useDatabaseDiagnosticsFeature } from "./serviceFeatures/useDatabaseDiagnostics";
import { installGlobalSecureWebFetch } from "./secureweb/globalFetch";
import { useSyncPerformanceDefaults } from "./serviceFeatures/syncPerformance";
import {
    installSecureWebXhrShim,
    installSecureWebRequestUrlShim,
    setSecureWebSettingsProvider,
    registerGatewayHost,
} from "./secureweb/envelope";

export type LiveSyncCore = LiveSyncBaseCore<ObsidianServiceContext, LiveSyncCommands>;
export default class ObsidianLiveSyncPlugin extends Plugin {
    core: LiveSyncCore;

    /**
     * Initialise service modules.
     */
    private initialiseServiceModules(
        core: LiveSyncBaseCore<ObsidianServiceContext, LiveSyncCommands>,
        services: InjectableServiceHub<ObsidianServiceContext>
    ): ServiceModules {
        const storageAccessManager = new StorageAccessManager();
        // If we want to implement to the other platform, implement ObsidianXXXXXService.
        const vaultAccess = new FileAccessObsidian(this.app, {
            storageAccessManager: storageAccessManager,
            vaultService: services.vault,
            settingService: services.setting,
            APIService: services.API,
            pathService: services.path,
        });
        const storageEventManager = new StorageEventManagerObsidian(this, core, {
            fileProcessing: services.fileProcessing,
            setting: services.setting,
            vaultService: services.vault,
            storageAccessManager: storageAccessManager,
            APIService: services.API,
        });
        const storageAccess = new ServiceFileAccessObsidian({
            API: services.API,
            setting: services.setting,
            fileProcessing: services.fileProcessing,
            vault: services.vault,
            appLifecycle: services.appLifecycle,
            storageEventManager: storageEventManager,
            storageAccessManager: storageAccessManager,
            vaultAccess: vaultAccess,
        });

        const databaseFileAccess = new ServiceDatabaseFileAccess({
            events: services.context.events,
            API: services.API,
            database: services.database,
            path: services.path,
            storageAccess: storageAccess,
            vault: services.vault,
        });

        const fileHandler = new ServiceFileHandler({
            events: services.context.events,
            API: services.API,
            databaseFileAccess: databaseFileAccess,
            conflict: services.conflict,
            setting: services.setting,
            fileProcessing: services.fileProcessing,
            vault: services.vault,
            path: services.path,
            replication: services.replication,
            storageAccess: storageAccess,
            fileReflectionProvenance: createFileReflectionProvenance(services.keyValueDB),
        });
        const rebuilder = new ServiceRebuilder({
            path: services.path,
            events: services.context.events,
            API: services.API,
            database: services.database,
            appLifecycle: services.appLifecycle,
            setting: services.setting,
            remote: services.remote,
            databaseEvents: services.databaseEvents,
            replication: services.replication,
            replicator: services.replicator,
            UI: services.UI,
            vault: services.vault,
            fileHandler: fileHandler,
            fileProcessing: services.fileProcessing,
            storageAccess: storageAccess,
            control: services.control,
        });
        return {
            rebuilder,
            fileHandler,
            databaseFileAccess,
            storageAccess,
        };
    }

    /**
     * @obsolete Use services.setting.saveSettingData instead. Save the settings to the disk. This is usually called after changing the settings in the code, to persist the changes.
     */
    async saveSettings() {
        await this.core.services.setting.saveSettingData();
    }

    constructor(app: App, manifest: PluginManifest) {
        super(app, manifest);
        setSecureWebSettingsProvider(() => this.core?.settings);
        this.register(installGlobalSecureWebFetch(() => this));
        this.register(installSecureWebXhrShim(() => this.core?.settings));
        this.register(installSecureWebRequestUrlShim(() => this));
        this.registerObsidianProtocolHandler("livesync-secureweb", (params) => {
            void this.handleSecureWebSetup(params);
        });
        // Maybe no more need to setNoticeClass, but for safety, set it in the constructor of the main plugin class.
        // TODO: remove this.
        setNoticeClass(Notice);

        const serviceHub = new ObsidianServiceHub(this);

        this.core = new LiveSyncBaseCore(
            serviceHub,
            (core, serviceHub) => {
                return this.initialiseServiceModules(core, serviceHub);
            },
            (core) => {
                const extraModules = [
                    new ModuleObsidianEvents(this, core),
                    new ModuleObsidianSettingDialogue(this, core),
                    new ModuleObsidianSettingsAsMarkdown(core),
                    new ModuleLog(this, core),
                    new ModuleObsidianDocumentHistory(this, core),
                    new ModuleObsidianGlobalHistory(this, core),
                    // new ModuleDev(this, core),
                    new SetupManager(core), // this should be moved to core?
                ];
                return extraModules;
            },
            (core) => {
                const addOns = [new ConfigSync(core), new HiddenFileSync(core), new LocalDatabaseMaintenance(core)];
                return addOns;
            },
            (core) => {
                //TODO Fix: useXXXX
                const featuresInitialiser = enableI18nFeature;
                const curriedFeature = () => featuresInitialiser(core);
                core.services.appLifecycle.onLayoutReady.addHandler(curriedFeature);
                const setupManager = core.getModule(SetupManager);
                const createInteractiveP2PReplication = createOpenReplicationUI(this.app);
                const replicator = useP2PReplicatorFeature(
                    core,
                    (_compatibilityReplicator, p2p) => createInteractiveP2PReplication(p2p),
                    createOpenRebuildUI(this.app),
                    {
                        prepareP2PSettings: useP2PSettingsPreparation(
                            core.services.API.webCompatFetch.bind(core.services.API)
                        ),
                    }
                );
                setupManager.registerP2PSetupConnectionProbe(replicator.connectionProbe);
                useP2PReplicatorCommands(core, replicator);
                useP2PReplicatorUI(core, core, replicator, createInteractiveP2PReplication(replicator));
                useObsidianReplicationRibbonFeature(core);
                useDatabaseDiagnosticsFeature(core);
                useJoinedDevicesFeature(core, serviceHub.context.noticeGroups);
                useRemoteConfiguration(core);

                useSetupProtocolFeature(core, setupManager);
                useSetupQRCodeFeature(core);
                useSetupURIFeature(core);
                useSetupManagerHandlersFeature(core, setupManager);
                useOfflineScanner(core);
                useSyncPerformanceDefaults(core);
                useRedFlagFeatures(core);
                useCheckRemoteSize(core);
                useInteractiveConflictResolutionFeature(core, (filename, conflictCheckResult) => {
                    return new ConflictResolveModal(this.app, filename, conflictCheckResult);
                });
                const compatibilityReview = useCompatibilityReview(
                    core,
                    createObsidianCompatibilityReviewUi(core.confirm)
                );
                useStartupLifecycleFeature(core, {
                    inviteToOnboarding: () => showOnboardingInvitation(core, setupManager),
                    waitForCompatibilityReview: () => compatibilityReview.openReview(),
                });
                useReviewHarness(core, this, compatibilityReview);
            }
        );
    }

    private async _startUp() {
        if (!(await this.core.services.control.onLoad())) return;
        const onReady = this.core.services.control.onReady.bind(this.core.services.control);
        this.app.workspace.onLayoutReady(onReady);
    }
    override onload() {
        void this._startUp();
    }
    private async handleSecureWebSetup(params: Record<string, string>) {
        const gateway = (params.gateway || "").trim();
        const db = (params.db || "vault").trim();
        const token = (params.token || "").trim();
        if (!gateway || !token) {
            new Notice("SecureWeb setup link is incomplete (gateway + token required).");
            return;
        }
        let normalizedGateway = gateway;
        try {
            const parsed = new URL(gateway);
            normalizedGateway = `${parsed.protocol}//${parsed.host}`;
        } catch {
            new Notice("SecureWeb setup link has an invalid gateway URL.");
            return;
        }
        // Register the host before settings are saved: the wizard's first
        // connection test runs pre-save and must already ride the sealed
        // transport (unsealed requests hit the gateway's blind-mode decoy).
        registerGatewayHost(normalizedGateway);
        // Settings live on the core, which initialises asynchronously —
        // wait briefly for it to exist.
        let settings: any;
        for (let i = 0; i < 20 && !settings; i += 1) {
            settings = (this.core as any)?.settings ?? (this as any).settings;
            if (!settings) {
                await new Promise((resolve) => window.setTimeout(resolve, 250));
            }
        }
        if (!settings) {
            new Notice("SecureWeb setup failed: plugin settings are not ready.");
            return;
        }
        // Persist the remote as a PLAINTEXT remote-configuration profile in
        // livesync's own connection-string format (`sls+https://…/?db=…`).
        // Writing plaintext top-level couchDB_* fields instead makes the
        // plugin migrate them into a passphrase-sealed profile that can never
        // be decrypted ("Failed to initialise the encryption key").
        let profileUri: string;
        try {
            const gw = new URL(normalizedGateway);
            const conn = new URL(`https://${gw.host}${gw.pathname.replace(/\/$/, "")}/`);
            conn.username = settings.couchDB_USER || "obsidian";
            conn.password = token;
            conn.searchParams.set("db", db || "vault");
            profileUri = `sls+${conn.toString()}`;
        } catch {
            new Notice("SecureWeb setup failed: could not build the connection string.");
            return;
        }
        settings.remoteConfigurations = {
            secureweb: {
                id: "secureweb",
                name: "SecureWeb",
                uri: profileUri,
                isEncrypted: false,
            },
        };
        settings.activeConfigurationId = "secureweb";
        // The replication core reads the flat fields (the PBKDF2 salt
        // lookup builds its URL from couchDB_URI + DBNAME) and selects the
        // replicator by remoteType — keep both in sync with the profile.
        settings.couchDB_URI = normalizedGateway;
        settings.couchDB_DBNAME = db || "vault";
        settings.couchDB_USER = settings.couchDB_USER || "obsidian";
        settings.couchDB_PASSWORD = token;
        settings.remoteType = "couchdb";
        settings.configPassphraseStore = "";
        // Purge legacy encrypted remote-config traps so nothing resurrects
        // an old connection over these values.
        settings.encryptedCouchDBConnection = "";
        settings.encryptedPassphrase = "";
        settings.encryptedIdDerivationKey = "";
        // Service identity: relay registry UUID of the sync service. Stored
        // persistently so the transport never needs deployment-specific
        // defaults (discovery remains the fallback).
        const serviceParam = (params.service || "").trim();
        if (/^[0-9a-fA-F-]{16,64}$/.test(serviceParam)) {
            settings.secureWebServiceId = serviceParam;
        }
        settings.isConfigured = true;
        // Document ids in the shared database are canonical: lowercased
        // (case-insensitive history) + NFC. Align this device with them so
        // lookups match instead of 404-ing on case/Unicode differences.
        settings.handleFilenameCaseSensitive = false;
        // Optional per-device path exclusions (regex). Used to keep huge
        // scanned PDFs off memory-limited devices — they still live on the
        // desktop and in the database.
        if (params.ignore && params.ignore.length <= 1024) {
            settings.syncIgnoreRegEx = params.ignore;
        }
        // Safe-by-default tuning: concurrency defaults to 40 (the upstream
        // setting default) unless the setup link explicitly overrides it.
        const conc = Number(params.conc ?? "40");
        if (Number.isFinite(conc) && conc > 0 && conc <= 40) {
            settings.concurrencyOfReadChunksOnline = conc;
        }
        const batch = Number(params.batch);
        if (Number.isFinite(batch) && batch > 0 && batch <= 50) {
            settings.batch_size = batch;
        }
        if (params.timeouts === "1") {
            settings.useTimeouts = true;
        }
        try {
            await this.saveSettings();
            new Notice(`SecureWeb configured: ${normalizedGateway} → ${settings.couchDB_DBNAME}`);
        } catch (err) {
            new Notice(`SecureWeb setup save failed: ${err instanceof Error ? err.message : String(err)}`);
        }
    }
    override onunload(): void {
        void this.core.services.control.onUnload().catch((error) => {
            this.core.services.API.addLog(
                "Failed to unload Self-hosted LiveSync: " + String(error),
                LOG_LEVEL_URGENT,
                "shutdown"
            );
        });
    }
}
