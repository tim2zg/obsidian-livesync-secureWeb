import { describe, expect, it, vi } from "vitest";
import {
    mergeRecommendedSyncExclusions,
    RECOMMENDED_SYNC_EXCLUSIONS,
    SYNC_PERFORMANCE_MIGRATION_KEY,
    useSyncPerformanceDefaults,
} from "./syncPerformance";

describe("SecureWeb sync performance defaults", () => {
    it("preserves user selectors and does not duplicate the recommended expressions", () => {
        const existing = "private/.*|[]|" + RECOMMENDED_SYNC_EXCLUSIONS[0];
        const merged = mergeRecommendedSyncExclusions(existing);
        expect(merged.startsWith(existing)).toBe(true);
        expect(mergeRecommendedSyncExclusions(merged)).toBe(merged);
        expect(merged.split("|[]|")).toHaveLength(4);
    });

    it.each([
        ["Analysis/Serie08.pdf.tmp", true],
        ["Analysis/Serie08.pdf.part", true],
        ["Downloads/lecture.pdf.crdownload", true],
        ["project/node_modules/package/index.js", true],
        ["project/__pycache__/module.pyc", true],
        ["_archive/ZZ__manim/media/texts/generated.svg", true],
        ["__manim/media/videos/generated.mp4", true],
        ["Analysis/Serie08.pdf", false],
        ["_concepts/Current.md", false],
        ["Excalidraw/My solution.excalidraw.md", false],
        ["_archive/Old study notes.md", false],
        ["media/images/Circuit.svg", false],
        ["project/source/main.py", false],
        ["notes/node_modules_overview.md", false],
    ])("selects generated files without excluding study material: %s", (path, excluded) => {
        const patterns = mergeRecommendedSyncExclusions("")
            .split("|[]|")
            .map((pattern) => new RegExp(pattern, "i"));
        expect(patterns.some((pattern) => pattern.test(path))).toBe(excluded);
    });

    function fixture() {
        const handlers: Array<() => Promise<boolean>> = [];
        const settings = { isConfigured: true, syncIgnoreRegEx: "private/.*" };
        const values = new Map<string, string>();
        const setting = {
            currentSettings: () => settings,
            config: {
                getValue: vi.fn(async (key: string, fallback: string) => values.get(key) ?? fallback),
                setValue: vi.fn(async (key: string, value: string) => {
                    values.set(key, value);
                }),
            },
            applyPartial: vi.fn(async (partial: Partial<typeof settings>, _saveImmediately: boolean) => {
                Object.assign(settings, partial);
            }),
        };
        const host = {
            services: {
                setting,
                appLifecycle: {
                    onSettingLoaded: {
                        addHandler: (handler: () => Promise<boolean>) => {
                            handlers.push(handler);
                        },
                    },
                },
            },
        } as unknown as Parameters<typeof useSyncPerformanceDefaults>[0];
        useSyncPerformanceDefaults(host);
        return { settings, setting, handlers, values };
    }

    it("saves exclusions before marking the migration and respects later user changes", async () => {
        const f = fixture();
        expect(await f.handlers[0]()).toBe(true);
        expect(f.setting.applyPartial).toHaveBeenCalledWith({ syncIgnoreRegEx: expect.any(String) }, true);
        expect(f.setting.applyPartial.mock.invocationCallOrder[0]).toBeLessThan(
            f.setting.config.setValue.mock.invocationCallOrder[0]
        );
        expect(f.values.get(SYNC_PERFORMANCE_MIGRATION_KEY)).toBe("1");
        f.settings.syncIgnoreRegEx = "user-revised-selector/";
        await f.handlers[0]();
        expect(f.setting.applyPartial).toHaveBeenCalledOnce();
        expect(f.settings.syncIgnoreRegEx).toBe("user-revised-selector/");
    });

    it("leaves an unconfigured device alone until setup is complete", async () => {
        const f = fixture();
        f.settings.isConfigured = false;
        expect(await f.handlers[0]()).toBe(true);
        expect(f.setting.applyPartial).not.toHaveBeenCalled();
        expect(f.setting.config.setValue).not.toHaveBeenCalled();
    });

    it("does not mark a failed settings save as a completed migration", async () => {
        const f = fixture();
        f.setting.applyPartial.mockRejectedValueOnce(new Error("settings unavailable"));
        await expect(f.handlers[0]()).rejects.toThrow("settings unavailable");
        expect(f.setting.config.setValue).not.toHaveBeenCalled();
    });
});
