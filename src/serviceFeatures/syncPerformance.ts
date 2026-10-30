import type { NecessaryServices } from "@vrtmrz/livesync-commonlib/compat/interfaces/ServiceModule";
import type { CustomRegExpSourceList } from "@vrtmrz/livesync-commonlib/compat/common/types";

export const SYNC_PERFORMANCE_MIGRATION_KEY = "secureweb-sync-performance-v1";

export const RECOMMENDED_SYNC_EXCLUSIONS = [
    "\\.(?:tmp|part|crdownload)$",
    "(?:^|/)(?:node_modules|__pycache__|\\.cache)/",
    "(?:^|/)(?:__manim|ZZ__manim)/media/",
] as const;

/** Preserve the user's selectors while adding the fork's generated-file exclusions. */
export function mergeRecommendedSyncExclusions(existing: string): CustomRegExpSourceList<"|[]|"> {
    const patterns = existing.split("|[]|").filter(Boolean);
    for (const pattern of RECOMMENDED_SYNC_EXCLUSIONS) {
        if (!patterns.includes(pattern)) patterns.push(pattern);
    }
    return patterns.join("|[]|") as CustomRegExpSourceList<"|[]|">;
}

/** Apply once per device, before pending events and ordinary files are replayed. */
export function useSyncPerformanceDefaults(host: NecessaryServices<"appLifecycle" | "setting", never>): void {
    const setting = host.services.setting;
    host.services.appLifecycle.onSettingLoaded.addHandler(async () => {
        const settings = setting.currentSettings();
        if (!settings.isConfigured || (await setting.config.getValue(SYNC_PERFORMANCE_MIGRATION_KEY, "")) === "1") {
            return true;
        }
        const previous = settings.syncIgnoreRegEx || "";
        const next = mergeRecommendedSyncExclusions(previous);
        if (next !== previous) await setting.applyPartial({ syncIgnoreRegEx: next }, true);
        // Keep the marker local. Later user edits to the selectors are respected.
        await setting.config.setValue(SYNC_PERFORMANCE_MIGRATION_KEY, "1");
        return true;
    });
}
