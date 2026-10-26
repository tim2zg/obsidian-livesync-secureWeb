import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const roots: string[] = [];
afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function scan(source: string) {
    const root = mkdtempSync(path.join(tmpdir(), "livesync-secret-guard-"));
    roots.push(root);
    mkdirSync(path.join(root, "utils"));
    mkdirSync(path.join(root, "src"));
    const scanner = path.join(root, "utils", "check-transport-secrets.mjs");
    writeFileSync(scanner, readFileSync(path.join(process.cwd(), "utils", "check-transport-secrets.mjs")));
    writeFileSync(path.join(root, "src", "fixture.ts"), source);
    return spawnSync(process.execPath, [scanner], { cwd: root, encoding: "utf8" });
}
describe("transport credential guard", () => {
    it("accepts non-secret documentation and test placeholders", () => {
        expect(scan('const secret = "swt_v2_fixture_only_not_a_credential";').status).toBe(0);
    });
    it.each([
        ["App Token", "swt_" + "v2_" + "a".repeat(64)],
        ["GitHub credential", "gh" + "p_" + "b".repeat(36)],
        ["recovery code", "SW-" + "REC-" + Array(4).fill("ABCDEF12").join("-")],
        ["private key", "-----BEGIN " + "PRIVATE KEY-----\n" + "c".repeat(64)],
    ])("rejects a %s without revealing its value", (_kind, secret) => {
        const result = scan(secret);
        expect(result.status).toBe(1);
        expect(result.stderr.split(path.sep).join("/")).toContain("src/fixture.ts:1:");
        expect(result.stdout + result.stderr).not.toContain(secret);
    });
});
