//! Wie lange braucht die Schlüsselableitung wirklich?
//!
//! Nicht als Prüfung gedacht, sondern als Messung: `cargo test kdf -- --nocapture`.
use std::time::Instant;

#[test]
fn kdf() {
    for (mib, iters) in [(64u32, 3u32), (256, 5), (1024, 2)] {
        let params = argon2::Params::new(mib * 1024, iters, 4, Some(32)).unwrap();
        let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut out = [0u8; 32];
        let start = Instant::now();
        a.hash_password_into(b"demopass", b"0123456789abcdef", &mut out).unwrap();
        println!("{mib} MiB, {iters} Durchgänge -> {:?}", start.elapsed());
    }
}
