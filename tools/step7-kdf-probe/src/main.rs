use argon2::{Algorithm, Argon2, Params, Version};
use std::time::Instant;
use zeroize::Zeroizing;

fn vm_hwm_kb() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse::<u64>()
                .expect("parse VmHWM");
        }
    }
    panic!("VmHWM not found");
}

/// Heap probe: heap-backed 32-byte secret wrapped in Zeroizing, read back
/// through the raw pointer after drop. Acknowledged UB, empirical only.
fn heap_probe() -> (bool, String) {
    let mut boxed: Box<[u8]> = vec![0u8; 32].into_boxed_slice();
    // Volatile fill so the pattern write cannot be dead-store-eliminated.
    unsafe {
        let p = boxed.as_mut_ptr();
        for i in 0..32 {
            std::ptr::write_volatile(p.add(i), 0xAAu8);
        }
    }
    let z = Zeroizing::new(boxed);
    let ptr: *const u8 = z.as_ptr();
    drop(z);
    let mut buf = [0u8; 32];
    unsafe {
        for i in 0..32 {
            buf[i] = std::ptr::read_volatile(ptr.add(i));
        }
    }
    let zeroed = buf.iter().all(|&b| b == 0);
    let hex: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    (zeroed, hex)
}

/// Control: identical heap allocation dropped WITHOUT Zeroizing. glibc tcache
/// clobbers the first 16 bytes of a freed chunk (fd + key), so bytes 16..32
/// are the discriminating region: 0xAA residue here means no wipe happened.
fn heap_control() -> String {
    let mut boxed: Box<[u8]> = vec![0u8; 32].into_boxed_slice();
    unsafe {
        let p = boxed.as_mut_ptr();
        for i in 0..32 {
            std::ptr::write_volatile(p.add(i), 0xAAu8);
        }
    }
    let ptr: *const u8 = boxed.as_ptr();
    drop(boxed);
    let mut buf = [0u8; 32];
    unsafe {
        for i in 0..32 {
            buf[i] = std::ptr::read_volatile(ptr.add(i));
        }
    }
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Stack probe: the Zeroizing array lives in an inner scope of THIS frame; the
/// readback happens after the scope ends, from the same still-live frame, into
/// a heap buffer (so the readback cannot itself reuse the probed stack slot).
#[inline(never)]
fn stack_probe() -> (bool, String) {
    let ptr: *const u8;
    {
        let mut arr = [0u8; 32];
        // Volatile fill so the pattern write cannot be dead-store-eliminated.
        unsafe {
            let p = arr.as_mut_ptr();
            for i in 0..32 {
                std::ptr::write_volatile(p.add(i), 0xAAu8);
            }
        }
        let z = Zeroizing::new(arr);
        ptr = z.as_ptr();
        unsafe { std::ptr::read_volatile(ptr) };
        // z drops here; zeroize wipes the stack slot with volatile writes.
    }
    let mut buf = vec![0u8; 32];
    unsafe {
        for i in 0..32 {
            buf[i] = std::ptr::read_volatile(ptr.add(i));
        }
    }
    let zeroed = buf.iter().all(|&b| b == 0);
    let hex: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    (zeroed, hex)
}

fn main() {
    // --- KDF probe: same call shape as jeliya-core derive_kek ---
    let salt = [0x42u8; 16];
    let password = "kdfprobe-password";
    let params = Params::new(19_456, 2, 1, Some(32)).expect("params");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let hwm_before = vm_hwm_kb();
    let t0 = Instant::now();
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), &salt, key.as_mut())
        .expect("argon2 derivation");
    let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let hwm_after = vm_hwm_kb();
    let delta_kb = hwm_after.saturating_sub(hwm_before);
    let delta_mib = delta_kb as f64 / 1024.0;

    // --- Zeroizing wipe probes ---
    let (heap_zeroed, heap_hex) = heap_probe();
    let heap_control_hex = heap_control();
    let (stack_zeroed, stack_hex) = stack_probe();

    println!(
        "{{\"vm_hwm_before_kb\":{},\"vm_hwm_after_kb\":{},\"vm_hwm_delta_kb\":{},\"vm_hwm_delta_mib\":{:.3},\"kdf_latency_ms\":{:.3},\"heap_probe_zeroed\":{},\"heap_probe_bytes_hex\":\"{}\",\"heap_control_bytes_hex\":\"{}\",\"stack_probe_zeroed\":{},\"stack_probe_bytes_hex\":\"{}\",\"key_first_byte_nonzero\":{}}}",
        hwm_before,
        hwm_after,
        delta_kb,
        delta_mib,
        latency_ms,
        heap_zeroed,
        heap_hex,
        heap_control_hex,
        stack_zeroed,
        stack_hex,
        key.iter().any(|&b| b != 0)
    );
}
