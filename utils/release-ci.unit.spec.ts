import { describe, expect, it } from "vitest";
import { assertReleaseCI } from "./release-ci.mjs";
const revision = "a".repeat(40);
const success = { head_sha: revision, event: "push", run_number: 10, status: "completed", conclusion: "success", html_url: "https://example.test/ci/10" };
describe("release CI gate", () => {
    it("accepts the latest successful push run for the release commit", () => {
        expect(assertReleaseCI([success], revision)).toEqual(success);
    });
    it.each([
        [],
        [{ ...success, head_sha: "b".repeat(40) }],
        [{ ...success, event: "pull_request" }],
        [{ ...success, status: "in_progress", conclusion: null }],
        [{ ...success, conclusion: "failure" }],
        [{ ...success, conclusion: "cancelled" }],
    ])("rejects missing, incomplete, or unsuccessful release checks %#", (...runs) => {
        expect(() => assertReleaseCI(runs, revision)).toThrow("requires its latest push run");
    });
    it("does not reuse an earlier success when a newer run failed", () => {
        const failed = { ...success, run_number: 11, conclusion: "failure" };
        expect(() => assertReleaseCI([success, failed], revision)).toThrow();
        expect(() => assertReleaseCI([failed, success], revision)).toThrow();
    });
});
