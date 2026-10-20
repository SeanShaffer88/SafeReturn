//! safereturn-pe-shell — the WinPE recovery shell binary.
//!
//! On Windows this runs the native Win32 front-end
//! (`safereturn_pe_shell::win32::run`). Everywhere else it is the
//! typed unsupported-platform error the contract promises: the
//! recovery shell is WinPE software, and saying so with the
//! engine's named error beats a panic or a silent exit.

#[cfg(not(windows))]
fn main() {
    let err = safereturn_core::CoreError::UnsupportedPlatform {
        feature: "the WinPE recovery shell",
    };
    eprintln!("Error: {err}");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    safereturn_pe_shell::win32::run();
}
