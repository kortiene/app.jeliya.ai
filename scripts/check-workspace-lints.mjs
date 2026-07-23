#!/usr/bin/env node
// Workspace-lints inheritance gate (issue #35). No npm dependencies.
//
// `unsafe_code = "forbid"` is declared once in the root `[workspace.lints.rust]`
// and binds only crates that opt in with `[lints] workspace = true`. A new
// workspace member that silently omits those three lines inherits nothing, and
// the workspace would quietly stop being unsafe-forbidden at exactly the moment
// it grows the crates that matter most (pairing transcript, identity keys).
// This check fails CI when any member of `[workspace] members` neither opts in
// nor records an explicit, reasoned exemption of the form
// `# workspace-lints-exemption: <boundary that requires unsafe, and why>`
// in its own Cargo.toml.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OPT_IN = /\[lints\][^[]*?^\s*workspace\s*=\s*true\s*$/ms;
const EXEMPTION = /^#\s*workspace-lints-exemption:\s*(\S.*)$/m;
/// An exemption must name the boundary and reason, not just tick a box.
const MIN_EXEMPTION_REASON_CHARS = 20;

/**
 * Validate every workspace member's lints opt-in under `rootDir`.
 * Returns a list of failure strings (empty = pass).
 */
export function checkWorkspaceLints(rootDir) {
  const failures = [];
  let rootManifest;
  try {
    rootManifest = readFileSync(join(rootDir, "Cargo.toml"), "utf8");
  } catch (err) {
    return [`Cargo.toml: could not read the root manifest: ${err.message}`];
  }

  const workspaceSection = rootManifest.match(/^\[workspace\]$([\s\S]*?)(?=^\[|\n*$(?![\s\S]))/m);
  const membersMatch = (workspaceSection ? workspaceSection[1] : "").match(
    /^members\s*=\s*\[([\s\S]*?)\]/m,
  );
  if (!membersMatch) {
    return ["Cargo.toml: could not find [workspace] members — the check cannot enumerate crates"];
  }
  const members = [...membersMatch[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  if (members.length === 0) {
    return ["Cargo.toml: [workspace] members is empty — the check cannot enumerate crates"];
  }
  if (!/^\[workspace\.lints\.rust\]$/m.test(rootManifest) || !/^unsafe_code\s*=\s*"forbid"$/m.test(rootManifest)) {
    failures.push(
      'Cargo.toml: [workspace.lints.rust] must declare unsafe_code = "forbid" — the property every member inherits',
    );
  }

  for (const member of members) {
    const manifestPath = `${member}/Cargo.toml`;
    let manifest;
    try {
      manifest = readFileSync(join(rootDir, manifestPath), "utf8");
    } catch (err) {
      failures.push(`${manifestPath}: could not read the member manifest: ${err.message}`);
      continue;
    }
    if (OPT_IN.test(manifest)) {
      continue;
    }
    const exemption = manifest.match(EXEMPTION);
    if (!exemption) {
      failures.push(
        `${manifestPath}: neither opts in to workspace lints ([lints] workspace = true) nor ` +
          "records a '# workspace-lints-exemption: <reason>' — the crate silently escapes " +
          'unsafe_code = "forbid"',
      );
      continue;
    }
    if (exemption[1].trim().length < MIN_EXEMPTION_REASON_CHARS) {
      failures.push(
        `${manifestPath}: the workspace-lints-exemption reason must name the boundary that ` +
          `requires unsafe and why (got ${JSON.stringify(exemption[1].trim())})`,
      );
    }
  }
  return failures;
}

const invokedDirectly =
  process.argv[1] && fileURLToPath(import.meta.url) === (await import("node:fs")).realpathSync(process.argv[1]);
if (invokedDirectly) {
  const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
  const failures = checkWorkspaceLints(process.argv[2] ?? repoRoot);
  if (failures.length > 0) {
    console.error(`workspace-lints-check: ${failures.length} finding(s)\n`);
    for (const failure of failures) console.error(`  ${failure}`);
    process.exit(1);
  }
  console.log("workspace-lints-check: OK — every workspace member inherits the workspace lints (or records a reasoned exemption).");
}
