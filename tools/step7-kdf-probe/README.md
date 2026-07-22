# Step 7 KDF / zeroize evidence probe

The measurement harness behind the "measured evidence" paragraph of the
[Step 7 re-review verdict](../../docs/phase-1-security-review.md#step-7-re-review-verdict-2026-07-22)
(findings F6/F8 closure evidence). Committed so the numbers are reproducible
and auditable, per the F10 standard the review itself set.

Deliberately **not** a workspace member: it pins the exact crypto versions the
review examined (`argon2 =0.5.3`, `aes-gcm =0.10.3`, `zeroize =1.9.0` — the
same resolved versions as the workspace `Cargo.lock` at pin `df28f6a`)
independently of the workspace graph. `Cargo.lock` here is committed.

## What it measures

1. **KDF memory target** — runs Argon2id with the `V1_KDF` parameters
   (m=19456 KiB, t=2, p=1, 32-byte output; the same call shape as
   `jeliya-core::identity::derive_kek`) and reports the `VmHWM` peak-RSS delta
   from `/proc/self/status`. Expected ≈ 19 MiB if the memory parameter is
   actually exercised.
2. **KDF latency** — wall-clock for one derivation.
3. **Zeroizing heap wipe (with control)** — fills a heap-backed 32-byte buffer
   with `0xAA`, wraps it in `Zeroizing`, drops it, and volatile-reads the freed
   memory through a retained raw pointer. A control run does the same WITHOUT
   `Zeroizing`. glibc's tcache overwrites the first 16 bytes of a freed chunk
   (fd pointer + key) in both cases, so **bytes 16..32 are the discriminating
   region**: zero with `Zeroizing`, `0xAA` residue without.
4. **Zeroizing stack wipe** — same pattern for a stack array dropped in an
   inner scope, re-probed from the same still-live frame into a heap buffer.

Reading freed/dead memory is undefined behavior; the probe is empirical
corroboration of the `zeroize` volatile-write mechanism, not a soundness
proof. Linux-only (`/proc/self/status`).

## Run it

```sh
cd tools/step7-kdf-probe
cargo build --release
./target/release/step7-kdf-probe
```

## Recorded transcript (2026-07-22, Step 7 re-review)

Linux x86-64, rustc 1.97.1, three consecutive runs:

```json
{"vm_hwm_before_kb":1748,"vm_hwm_after_kb":21156,"vm_hwm_delta_kb":19408,"vm_hwm_delta_mib":18.953,"kdf_latency_ms":29.387,"heap_probe_zeroed":false,"heap_probe_bytes_hex":"6196c344cbbf0000dad3b1b9f901752200000000000000000000000000000000","heap_control_bytes_hex":"e191c344cbbf0000dad3b1b9f9017522aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","stack_probe_zeroed":true,"stack_probe_bytes_hex":"0000000000000000000000000000000000000000000000000000000000000000","key_first_byte_nonzero":true}
{"vm_hwm_before_kb":1748,"vm_hwm_after_kb":21156,"vm_hwm_delta_kb":19408,"vm_hwm_delta_mib":18.953,"kdf_latency_ms":29.307,"heap_probe_zeroed":false,"heap_probe_bytes_hex":"748e72bf38b00000d6c934fbbbc6a81800000000000000000000000000000000","heap_control_bytes_hex":"f48972bf38b00000d6c934fbbbc6a818aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","stack_probe_zeroed":true,"stack_probe_bytes_hex":"0000000000000000000000000000000000000000000000000000000000000000","key_first_byte_nonzero":true}
{"vm_hwm_before_kb":1744,"vm_hwm_after_kb":21156,"vm_hwm_delta_kb":19412,"vm_hwm_delta_mib":18.957,"kdf_latency_ms":21.250,"heap_probe_zeroed":false,"heap_probe_bytes_hex":"49db6ce51bc800006ec2167391ce301a00000000000000000000000000000000","heap_control_bytes_hex":"c9dc6ce51bc800006ec2167391ce301aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","stack_probe_zeroed":true,"stack_probe_bytes_hex":"0000000000000000000000000000000000000000000000000000000000000000","key_first_byte_nonzero":true}
```

Interpretation:

- **VmHWM delta ≈ 18.95 MiB** across runs — the m=19456 KiB memory parameter
  is real (an ineffective memory setting would show a near-zero delta).
- **Latency 21–29 ms** on this machine (a separate review-time run on a loaded
  machine measured ~41 ms; the order of magnitude is what matters vs the
  in-tree test's 1 ms floor — see verdict condition 2).
- **Heap probe**: discriminating bytes 16..32 read all-zero with `Zeroizing`
  vs `aa…aa` in the control — the wipe demonstrably ran. `heap_probe_zeroed`
  is `false` when tcache metadata occupies bytes 0..16 (both probe and
  control), which is allocator behavior, not a missing wipe.
- **Stack probe**: all 32 bytes zero after the inner-scope drop.
- **Feature resolution** (separate check, run in the workspace root):
  `cargo tree --locked -p jeliya-core -e features` shows the `zeroize`
  feature active on `argon2` and `aes-gcm` (propagating to `aes`/`cipher`).
