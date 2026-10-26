import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");
const listed = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], {
    cwd: root, encoding: "utf8",
});
const patterns = [
    ["App Token literal", /\bswt_(?:v2_)?[a-fA-F0-9]{32,}\b/],
    ["recovery code literal", /\bSW-REC-(?:[A-Fa-f0-9]{8}-){3}[A-Fa-f0-9]{8}\b/],
    ["GitHub credential literal", /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/],
    ["private key block", /-----BEGIN (?:OPENSSH |RSA |EC |)PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{32,}/],
];
const extensions = new Set([".ts", ".js", ".mjs", ".cjs", ".json", ".md", ".yml", ".yaml", ".txt", ".env"]);
function walk(directory) {
    return fs.existsSync(directory) ? fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
        const filename = path.join(directory, entry.name);
        return entry.isDirectory() ? walk(filename) : entry.isFile() ? [path.relative(root, filename)] : [];
    }) : [];
}
const files = listed.status === 0 ? listed.stdout.split("\0").filter(Boolean)
    : ["src", "docs", "utils", ".github"].flatMap(name => walk(path.join(root, name)));
const findings = [];
for (const filename of new Set(files)) {
    const full = path.join(root, filename);
    if (!extensions.has(path.extname(filename)) || !fs.existsSync(full)) continue;
    const text = fs.readFileSync(full, "utf8");
    for (const [category, pattern] of patterns) {
        const match = pattern.exec(text);
        if (match) findings.push(`${filename}:${text.slice(0, match.index).split("\n").length}: ${category}`);
    }
}
if (findings.length) {
    console.error("Potential credentials found. Values are intentionally omitted:\n" + findings.join("\n"));
    process.exitCode = 1;
} else console.log("Transport credential scan passed; no token literals or private key blocks found.");
