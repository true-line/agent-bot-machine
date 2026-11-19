use std::{env, path::PathBuf, process::Command};

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    println!("cargo:rerun-if-changed=native/DeviceEnclave.swift");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        _ => panic!("unsupported macOS architecture"),
    };
    let deployment = env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "11.0".into());
    let status = Command::new("/usr/bin/xcrun")
        .args([
            "swiftc",
            "-target",
            &format!("{arch}-apple-macosx{deployment}"),
            "-O",
            "-parse-as-library",
            "-emit-library",
            "-static",
            "native/DeviceEnclave.swift",
            "-o",
        ])
        .arg(out.join("libdevice_enclave.a"))
        .status()
        .expect("compile native device provider");
    assert!(
        status.success(),
        "native device provider compilation failed"
    );
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=device_enclave");
    // Swift back-deployment archives are toolchain inputs. Link them at
    // build time; the installed binary loads Swift from the operating system.
    let swiftc = Command::new("/usr/bin/xcrun")
        .args(["--find", "swiftc"])
        .output()
        .expect("locate Swift toolchain");
    assert!(swiftc.status.success(), "cannot find Swift toolchain");
    let toolchain = PathBuf::from(std::str::from_utf8(&swiftc.stdout).unwrap().trim());
    let libraries = toolchain
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("lib/swift/macosx");
    println!("cargo:rustc-link-search=native={}", libraries.display());
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    for framework in ["CryptoKit", "Foundation", "LocalAuthentication", "Security"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
