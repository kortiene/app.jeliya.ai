import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { checkWorkspaceLints } from "./check-workspace-lints.mjs";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));

const ROOT_MANIFEST = `[workspace]
members = ["crates/good", "crates/bad", "crates/exempt"]
resolver = "2"

[workspace.lints.rust]
unsafe_code = "forbid"
`;

function fixtureWorkspace({ badManifest, exemptManifest }) {
  const root = mkdtempSync(join(tmpdir(), "lints-check-"));
  writeFileSync(join(root, "Cargo.toml"), ROOT_MANIFEST);
  for (const [name, body] of [
    ["good", '[package]\nname = "good"\n\n[lints]\nworkspace = true\n'],
    ["bad", badManifest],
    ["exempt", exemptManifest],
  ]) {
    mkdirSync(join(root, "crates", name), { recursive: true });
    writeFileSync(join(root, "crates", name, "Cargo.toml"), body);
  }
  return root;
}

test("a member with neither the opt-in nor an exemption fails the check", () => {
  const root = fixtureWorkspace({
    badManifest: '[package]\nname = "bad"\n',
    exemptManifest:
      '# workspace-lints-exemption: wasm-bindgen FFI boundary requires unsafe in generated glue\n[package]\nname = "exempt"\n',
  });
  try {
    const failures = checkWorkspaceLints(root);
    assert.equal(failures.length, 1, failures.join("\n"));
    assert.match(failures[0], /crates\/bad\/Cargo\.toml/);
    assert.match(failures[0], /neither opts in/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a reasoned exemption passes; a bare or empty one fails", () => {
  const root = fixtureWorkspace({
    badManifest: '# workspace-lints-exemption: because\n[package]\nname = "bad"\n',
    exemptManifest:
      '# workspace-lints-exemption: wasm-bindgen FFI boundary requires unsafe in generated glue\n[package]\nname = "exempt"\n',
  });
  try {
    const failures = checkWorkspaceLints(root);
    assert.equal(failures.length, 1, failures.join("\n"));
    assert.match(failures[0], /crates\/bad\/Cargo\.toml/);
    assert.match(failures[0], /must name the boundary/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a missing member manifest and a lint-less root both fail closed", () => {
  const root = mkdtempSync(join(tmpdir(), "lints-check-"));
  try {
    writeFileSync(
      join(root, "Cargo.toml"),
      '[workspace]\nmembers = ["crates/ghost"]\nresolver = "2"\n',
    );
    const failures = checkWorkspaceLints(root);
    assert.equal(failures.length, 2, failures.join("\n"));
    assert.match(failures[0], /unsafe_code = "forbid"/);
    assert.match(failures[1], /crates\/ghost\/Cargo\.toml: could not read/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a root manifest without [workspace] members fails closed", () => {
  const root = mkdtempSync(join(tmpdir(), "lints-check-"));
  try {
    writeFileSync(join(root, "Cargo.toml"), '[package]\nname = "solo"\n');
    const failures = checkWorkspaceLints(root);
    assert.equal(failures.length, 1, failures.join("\n"));
    assert.match(failures[0], /could not find \[workspace\] members/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the real repository passes with every current member opted in", () => {
  assert.deepEqual(checkWorkspaceLints(repoRoot), []);
});
