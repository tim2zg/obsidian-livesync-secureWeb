import { readFileSync } from "node:fs";
import { minimatch } from "minimatch";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

type Trigger = "push" | "pull_request";
type Workflow = {
    on?: Partial<Record<Trigger, { paths?: string[]; types?: string[] }>>;
};

function readWorkflow(filename: string): Workflow {
    const source = readFileSync(new URL(`../.github/workflows/${filename}`, import.meta.url), "utf8");
    return parse(source) as Workflow;
}

function matchesAnyPath(patterns: string[], filename: string): boolean {
    return patterns.some((pattern) => minimatch(filename, pattern));
}

const unitWorkflow = readWorkflow("unit-ci.yml");

describe("CI workflow path filters", () => {
    it.each(["push", "pull_request"] as const)("runs unit CI for required inputs on %s", (trigger) => {
        const patterns = unitWorkflow.on?.[trigger]?.paths ?? [];
        const requiredInputs = [
            "manifest.json",
            "updates.md",
            "_tools/bakei18n.ts",
            "terser.config.mjs",
            "utils/check-compatibility.js",
            "utils/livesync-commonlib-version.test.ts",
            "utils/livesync-commonlib-version.ts",
            "utils/ci-path-filters.unit.spec.ts",
            "utils/cli-ci.unit.spec.ts",
            ".github/workflows/cli-docker.yml",
            ".github/workflows/cli-deno-tests.yml",
            ".github/workflows/cli-p2p-tests.yml",
            ".github/workflows/cli-docker-validation.yml",
        ];

        expect(requiredInputs.filter((filename) => !matchesAnyPath(patterns, filename))).toEqual([]);
        expect(matchesAnyPath(patterns, "utils/unrelated.unit.spec.ts")).toBe(false);
    });
});
