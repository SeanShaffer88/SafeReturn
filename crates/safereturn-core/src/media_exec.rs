//! Media execution (S4): the side of media creation that touches
//! the machine. The engine hands a *confirmed* plan to a
//! `MediaExecutor`; planning, token validation, and target-drift
//! re-checks all happen before this trait is called, and the executor
//! runs exactly the steps in the plan — it makes no decisions of its
//! own.
//!
//! Executors:
//! - `UnsupportedExecutor` — every platform's honest default until a
//!   real build is wired: creating media returns the typed
//!   unsupported-platform error. Shells on non-Windows use this.
//! - `WindowsAdkExecutor` (Windows only) — renders each plan step to
//!   the documented ADK/DISM command (Microsoft Learn: WinPE for
//!   Windows 11, MakeWinPEMedia command-line options, DISM image
//!   management) and runs it. Defense in depth: even on Windows it
//!   refuses to start unless the SR_MEDIA_LIVE=1 environment switch
//!   is set, so no ambient call — a test, a stray code path — can
//!   ever erase a device. CI compiles this code (windows all-targets
//!   check) but never runs it: the only execution path is the
//!   env-gated, #[ignore]d live test.
//!
//! STATUS: compile-verified only. No media has ever been built by
//! this code; the on-machine session in docs/S4_NOTES.md owns the
//! runtime verification.

use crate::error::{CoreError, Result};
use crate::media::MediaPlan;
#[cfg(windows)]
use crate::media::{write_media_manifest, MediaStep};

/// Runs a confirmed media plan. `progress` receives (steps done,
/// total steps) after each step completes.
pub trait MediaExecutor {
    fn execute(&self, plan: &MediaPlan, progress: &mut dyn FnMut(u64, u64)) -> Result<()>;
}

/// The executor for platforms (and moments) where creating media is
/// not something this build can do.
pub struct UnsupportedExecutor;

impl MediaExecutor for UnsupportedExecutor {
    fn execute(&self, _plan: &MediaPlan, _progress: &mut dyn FnMut(u64, u64)) -> Result<()> {
        Err(CoreError::UnsupportedPlatform {
            feature: "creating recovery media",
        })
    }
}

/// The executor a shell should use for the host platform: the ADK
/// executor on Windows (still SR_MEDIA_LIVE-gated), the unsupported
/// executor everywhere else.
#[cfg(windows)]
pub fn platform_executor(target_spec: String) -> Box<dyn MediaExecutor> {
    Box::new(WindowsAdkExecutor::new(target_spec))
}

#[cfg(not(windows))]
pub fn platform_executor(_target_spec: String) -> Box<dyn MediaExecutor> {
    Box::new(UnsupportedExecutor)
}

pub const MEDIA_LIVE_ENV: &str = "SR_MEDIA_LIVE";

#[cfg(windows)]
pub struct WindowsAdkExecutor {
    /// MakeWinPEMedia /UFD destination, e.g. "F:" (the USB drive as
    /// the operator's machine enumerated it — supplied by the shell,
    /// which also supplied the matching target facts at plan time).
    target_spec: String,
    /// ADK install root. The default is the documented install
    /// location for the Windows ADK.
    adk_root: std::path::PathBuf,
    /// copype working directory (created fresh per build).
    work_dir: std::path::PathBuf,
}

#[cfg(windows)]
impl WindowsAdkExecutor {
    pub fn new(target_spec: String) -> Self {
        Self {
            target_spec,
            adk_root: std::path::PathBuf::from(
                r"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit",
            ),
            work_dir: std::env::temp_dir().join("safereturn-winpe"),
        }
    }

    pub fn with_adk_root(mut self, adk_root: std::path::PathBuf) -> Self {
        self.adk_root = adk_root;
        self
    }

    fn pe_root(&self) -> std::path::PathBuf {
        self.adk_root.join("Windows Preinstallation Environment")
    }

    /// Run one external step; a nonzero exit is a named failure that
    /// stops the build (later steps never run against a half-serviced
    /// image presented as success).
    fn run(&self, what: &str, program: &str, args: &[String]) -> Result<()> {
        let status = std::process::Command::new(program)
            .args(args)
            .env("WinPERoot", self.pe_root())
            .status()
            .map_err(|e| CoreError::Io {
                path: None,
                source: std::io::Error::other(format!(
                    "could not start {what} ({program}): {e}. Is the Windows ADK with the WinPE add-on installed?"
                )),
            })?;
        if !status.success() {
            return Err(CoreError::Io {
                path: None,
                source: std::io::Error::other(format!(
                    "{what} failed (exit {status}). The media was NOT created; the target device may be partially written — rebuild it before trusting it."
                )),
            });
        }
        Ok(())
    }

    fn run_batch(&self, what: &str, batch: &std::path::Path, args: &[String]) -> Result<()> {
        let mut full: Vec<String> = vec!["/C".to_string(), batch.to_string_lossy().into_owned()];
        full.extend(args.iter().cloned());
        self.run(what, "cmd.exe", &full)
    }
}

#[cfg(windows)]
fn rel_path(rel: &str) -> std::path::PathBuf {
    rel.split('/').collect()
}

#[cfg(windows)]
impl MediaExecutor for WindowsAdkExecutor {
    fn execute(&self, plan: &MediaPlan, progress: &mut dyn FnMut(u64, u64)) -> Result<()> {
        if std::env::var(MEDIA_LIVE_ENV).as_deref() != Ok("1") {
            return Err(CoreError::LiveNotEnabled {
                env_var: MEDIA_LIVE_ENV,
            });
        }
        let pe = self.pe_root();
        let work = &self.work_dir;
        let mount = work.join("mount");
        let image_file = work.join("media").join("sources").join("boot.wim");
        let total = plan.steps.len() as u64;
        for (i, step) in plan.steps.iter().enumerate() {
            match step {
                MediaStep::Copype { arch } => {
                    self.run_batch(
                        "copype",
                        &pe.join("copype.cmd"),
                        &[arch.clone(), work.to_string_lossy().into_owned()],
                    )?;
                }
                MediaStep::MountImage => {
                    self.run(
                        "DISM mount",
                        "dism.exe",
                        &[
                            "/Mount-Image".to_string(),
                            format!("/ImageFile:{}", image_file.display()),
                            "/Index:1".to_string(),
                            format!("/MountDir:{}", mount.display()),
                        ],
                    )?;
                }
                MediaStep::AddOptionalComponent { name } => {
                    let oc_dir = pe.join("amd64").join("WinPE_OCs");
                    let cab = oc_dir.join(format!("{name}.cab"));
                    self.run(
                        &format!("DISM add {name}"),
                        "dism.exe",
                        &[
                            format!("/Image:{}", mount.display()),
                            "/Add-Package".to_string(),
                            format!("/PackagePath:{}", cab.display()),
                        ],
                    )?;
                    // Locale cab, when the ADK ships one (Learn's
                    // documented practice: neutral cab, then the
                    // language-specific cab of the same name).
                    let locale = oc_dir.join("en-us").join(format!("{name}_en-us.cab"));
                    if locale.exists() {
                        self.run(
                            &format!("DISM add {name} (en-us)"),
                            "dism.exe",
                            &[
                                format!("/Image:{}", mount.display()),
                                "/Add-Package".to_string(),
                                format!("/PackagePath:{}", locale.display()),
                            ],
                        )?;
                    }
                }
                MediaStep::AddDriver { inf_path } => {
                    let mut args = vec![
                        format!("/Image:{}", mount.display()),
                        "/Add-Driver".to_string(),
                        format!("/Driver:{inf_path}"),
                    ];
                    if std::path::Path::new(inf_path).is_dir() {
                        args.push("/Recurse".to_string());
                    }
                    self.run(&format!("DISM add driver {inf_path}"), "dism.exe", &args)?;
                }
                MediaStep::CopyPayloadToImage {
                    source_path,
                    image_rel,
                } => {
                    let dest = mount.join(rel_path(image_rel));
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| crate::error::io_at(&parent.to_path_buf(), e))?;
                    }
                    std::fs::copy(source_path, &dest).map_err(|e| crate::error::io_at(&dest, e))?;
                }
                MediaStep::CopyPayloadToMedia {
                    source_path,
                    media_rel,
                } => {
                    let dest = work.join("media").join(rel_path(media_rel));
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| crate::error::io_at(&parent.to_path_buf(), e))?;
                    }
                    std::fs::copy(source_path, &dest).map_err(|e| crate::error::io_at(&dest, e))?;
                }
                MediaStep::UnmountAndCommit => {
                    self.run(
                        "DISM unmount/commit",
                        "dism.exe",
                        &[
                            "/Unmount-Image".to_string(),
                            format!("/MountDir:{}", mount.display()),
                            "/Commit".to_string(),
                        ],
                    )?;
                }
                MediaStep::MakeMedia { bootex } => {
                    let mut args = vec!["/UFD".to_string()];
                    if *bootex {
                        args.push("/bootex".to_string());
                    }
                    args.push(work.to_string_lossy().into_owned());
                    args.push(self.target_spec.clone());
                    self.run_batch("MakeWinPEMedia", &pe.join("MakeWinPEMedia.cmd"), &args)?;
                }
            }
            progress(i as u64 + 1, total);
        }
        // The manifest lands on the finished media's boot partition
        // root, where verify_media will look for it.
        let media_root = std::path::PathBuf::from(format!(
            "{}\\",
            self.target_spec.trim_end_matches(['\\', '/'])
        ));
        write_media_manifest(&media_root, plan, crate::engine::now_unix())?;
        Ok(())
    }
}
