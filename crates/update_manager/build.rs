// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

// Windows erfordert ein asInvoker-Manifest für Binärdateien mit UAC-Schlüsselwörtern im Namen.
// Windows requires an asInvoker manifest for binaries with UAC keywords in their name.
fn main() {
    #[cfg(target_os = "windows")]
    {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let manifest_path = std::path::Path::new(&manifest_dir)
            .join("update_manager.exe.manifest")
            .to_string_lossy()
            .into_owned();

        println!("cargo:rerun-if-changed={manifest_path}");
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{manifest_path}");
    }
}
