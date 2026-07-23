import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { checkWorkspaceLints } from "./check-workspace-lints.mjs";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));

const GOOD_LINTS = "[lints]\nworkspace = true\n";
const ROOT_LINTS = '[workspace.lints.rust]\nunsafe_code = "forbid"\n';

/** Write a minimal REAL crate `cargo metadata` can resolve: a manifest plus an
 *  empty `src/lib.rs` (metadata needs target discovery, not compilation). */
function writeCrate(root, dir, name, { lints = "", deps = "", exemption = "" } = {}) {
  mkdirSync(join(root, dir, "src"), { recursive: true });
  writeFileSync(join(root, dir, "src", "lib.rs"), "");
  writeFileSync(
    join(root, dir, "Cargo.toml"),
    `${exemption}[package]\nname = "${name}"\nversion = "0.0.0"\nedition = "2021"\n\n${deps}${lints}`,
  );
}

/** A temp workspace whose root lists only the crates in `members`. */
function fixtureRoot(members, rootLints = ROOT_LINTS) {
  const root = mkdtempSync(join(tmpdir(), "lints-check-"));
  writeFileSync(
    join(root, "Cargo.toml"),
    `[workspace]\nmembers = [${members.map((m) => `"${m}"`).join(", ")}]\nresolver = "2"\n\n${rootLints}`,
  );
  return root;
}

test("a listed member with neither the opt-in nor an exemption fails the check", () => {
  const root = fixtureRoot(["crates/good", "crates/bad"]);
  try {
    writeCrate(root, "crates/good", "good", { lints: GOOD_LINTS });
    writeCrate(root, "crates/bad", "bad");
    const failures = checkWorkspaceLints(root);
    assert.equal(failures.length, 1, failures.join("\n"));
    assert.match(failures[0], /crates\/bad\/Cargo\.toml/);
    assert.match(failures[0], /neither opts in/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an in-tree path dependency is a resolved member and cannot escape the gate", () => {
  // Cargo admits path dependencies inside the workspace directory as members
  // automatically — they never appear in the root `members` array, which is
  // exactly why the check enumerates via `cargo metadata`, not the manifest.
  const root = fixtureRoot(["crates/good"]);
  try {
    writeCrate(root, "crates/good", "good", {
      lints: GOOD_LINTS,
      deps: '[dependencies]\nsneaky = { path = "../sneaky" }\n\n',
    });
    writeCrate(root, "crates/sneaky", "sneaky");
    const failures = checkWorkspaceLints(root);
    assert.equal(failures.length, 1, failures.join("\n"));
    assert.match(failures[0], /crates\/sneaky\/Cargo\.toml/);
    assert.match(failures[0], /neither opts in/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a reasoned exemption passes; a bare one fails", () => {
  const root = fixtureRoot(["crates/bare", "crates/exempt"]);
  try {
    writeCrate(root, "crates/bare", "bare", {
      exemption: "# workspace-lints-exemption: because\n",
    });
    writeCrate(root, "crates/exempt", "exempt", {
      exemption:
        "# workspace-lints-exemption: wasm-bindgen FFI boundary requires unsafe in generated glue\n",
    });
    const failures = checkWorkspaceLints(root);
    assert.equal(failures.length, 1, failures.join("\n"));
    assert.match(failures[0], /crates\/bare\/Cargo\.toml/);
    assert.match(failures[0], /must name the boundary/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("unsafe_code = forbid in the wrong table does not satisfy the root gate", () => {
  // The value must live in [workspace.lints.rust] — the table members inherit
  // from — not merely appear somewhere in the root manifest.
  const root = fixtureRoot(
    ["crates/good"],
    '[workspace.metadata]\nunsafe_code = "forbid"\n\n[workspace.lints.rust]\nrust_2018_idioms = "warn"\n',
  );
  try {
    writeCrate(root, "crates/good", "good", { lints: GOOD_LINTS });
    const failures = checkWorkspaceLints(root);
    assert.equal(failures.length, 1, failures.join("\n"));
    assert.match(failures[0], /\[workspace\.lints\.rust\] table must declare unsafe_code = "forbid"/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a root manifest cargo cannot resolve fails closed", () => {
  const root = fixtureRoot(["crates/ghost"]); // listed member has no manifest
  try {
    const failures = checkWorkspaceLints(root);
    assert.ok(failures.length >= 1, failures.join("\n"));
    assert.ok(
      failures.some((f) => f.includes("cargo metadata failed")),
      failures.join("\n"),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the real repository passes with every current member opted in", () => {
  assert.deepEqual(checkWorkspaceLints(repoRoot), []);
});
