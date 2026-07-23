#!/usr/bin/env node
// Workspace-lints inheritance gate (issue #35). No npm dependencies.
//
// `unsafe_code = "forbid"` is declared once in the root `[workspace.lints.rust]`
// and binds only crates that opt in with `[lints] workspace = true`. A new
// workspace member that silently omits those three lines inherits nothing, and
// the workspace would quietly stop being unsafe-forbidden at exactly the moment
// it grows the crates that matter most (pairing transcript, identity keys).
//
// Membership is enumerated through `cargo metadata --no-deps` — the resolver's
// own answer — NOT by parsing the root manifest's `members` array: Cargo also
// admits in-tree path dependencies as workspace members automatically, so a
// crate can join the workspace without ever appearing in that array. This
// check fails CI when any resolved member neither opts in nor records an
// explicit, reasoned exemption of the form
// `# workspace-lints-exemption: <boundary that requires unsafe, and why>`
// in its own Cargo.toml, and when the root `[workspace.lints.rust]` table
// itself no longer forbids unsafe code.

import { readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const OPT_IN = /\[lints\][^[]*?^\s*workspace\s*=\s*true\s*$/ms;
const EXEMPTION = /^#\s*workspace-lints-exemption:\s*(\S.*)$/m;
/// An exemption must name the boundary and reason, not just tick a box.
const MIN_EXEMPTION_REASON_CHARS = 20;

/** The body of one TOML table (e.g. `[workspace.lints.rust]`): the text from
 *  its header line to the next `[` table header (or EOF). `null` if absent. */
function tomlTableBody(manifest, header) {
  const match = manifest.match(
    new RegExp(
      `^\\[${header.replace(/\./g, "\\.")}\\]\\s*$([\\s\\S]*?)(?=^\\s*\\[|(?![\\s\\S]))`,
      "m",
    ),
  );
  return match ? match[1] : null;
}

/**
 * Validate every RESOLVED workspace member's lints opt-in under `rootDir`.
 * Returns a list of failure strings (empty = pass). Fails closed when cargo
 * cannot enumerate the workspace.
 */
export function checkWorkspaceLints(rootDir) {
  const failures = [];

  let rootManifest;
  try {
    rootManifest = readFileSync(join(rootDir, "Cargo.toml"), "utf8");
  } catch (err) {
    return [`Cargo.toml: could not read the root manifest: ${err.message}`];
  }
  // The property every member inherits must live in the EXACT table members
  // inherit from — `unsafe_code = "forbid"` appearing anywhere else (e.g.
  // `[workspace.metadata]`) must not satisfy this gate.
  const lintsRust = tomlTableBody(rootManifest, "workspace.lints.rust");
  if (lintsRust === null || !/^unsafe_code\s*=\s*"forbid"\s*$/m.test(lintsRust)) {
    failures.push(
      'Cargo.toml: the [workspace.lints.rust] table must declare unsafe_code = "forbid" — the property every member inherits',
    );
  }

  // Authoritative membership: the resolver's answer, which includes in-tree
  // path dependencies that never appear in the root `members` array.
  const metadata = spawnSync(
    "cargo",
    [
      "metadata",
      "--no-deps",
      "--format-version",
      "1",
      "--manifest-path",
      join(rootDir, "Cargo.toml"),
    ],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  if (metadata.status !== 0) {
    failures.push(
      `cargo metadata failed (the gate fails closed — membership cannot be enumerated): ${(metadata.stderr || "").trim()}`,
    );
    return failures;
  }
  let packages;
  try {
    packages = JSON.parse(metadata.stdout).packages;
  } catch (err) {
    return [...failures, `cargo metadata output was not parseable JSON: ${err.message}`];
  }
  if (!Array.isArray(packages) || packages.length === 0) {
    return [
      ...failures,
      "cargo metadata reported no workspace members — the check cannot enumerate crates",
    ];
  }

  for (const pkg of packages) {
    const manifestPath = relative(rootDir, pkg.manifest_path) || pkg.manifest_path;
    let manifest;
    try {
      manifest = readFileSync(pkg.manifest_path, "utf8");
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
  console.log(
    "workspace-lints-check: OK — every resolved workspace member inherits the workspace lints (or records a reasoned exemption).",
  );
}
