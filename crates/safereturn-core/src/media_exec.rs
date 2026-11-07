//! Media execution (S4): the side of media creation that could touch
//! the machine. The engine validates a plan token and compares the
//! supplied target facts before calling a `MediaExecutor`; those
//! facts do not by themselves prove the identity of a physical disk.
//!
//! `UnsupportedExecutor` refuses on non-Windows. `WindowsAdkExecutor`
//! retains the proposed ADK/DISM steps, but always refuses before
//! running any command or writing anything: its independent target
//! selector has not been bound to the confirmed physical device or
//! checked against protected disks. `SR_MEDIA_LIVE=1` cannot bypass
//! this safety fence. Custom executors are supplied by the caller and
//! are not made safe by the built-in executor's fence.
//!
//! No media has been built by this code. See docs/S4_NOTES.md for
//! the requirements before live execution can be reconsidered.

use crate::error::{CoreError, Result};
use crate::media::MediaPlan;
#[cfg(any(windows, test))]
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

/// The executor a shell should use for the host platform. The Windows
/// executor is currently safety-disabled; other platforms report that
/// media creation is unsupported.
#[cfg(windows)]
pub fn platform_executor(target_spec: String) -> Box<dyn MediaExecutor> {
    Box::new(WindowsAdkExecutor::new(target_spec))
}

#[cfg(not(windows))]
pub fn platform_executor(_target_spec: String) -> Box<dyn MediaExecutor> {
    Box::new(UnsupportedExecutor)
}

pub const MEDIA_LIVE_ENV: &str = "SR_MEDIA_LIVE";

/// Sent with every media preview so shells can disclose that the
/// built-in executor is not available, including in JSON output.
pub const MEDIA_CREATION_UNAVAILABLE_WARNING_ID: &str = "media.creation_unavailable";
pub const MEDIA_CREATION_UNAVAILABLE_MESSAGE: &str = "SafeReturn's built-in recovery media creation is disabled because it cannot yet verify that the selected drive is the confirmed target or protect the PC and backup drives. You can still preview or verify media; wait for a version with verified target selection.";

/// This fence is intentionally unconditional. Before changing it,
/// bind the actual Windows erase target to the confirmed physical
/// identity, enforce protected-disk checks, address device changes
/// during execution, and validate the complete path on safe hardware.
/// An environment switch or matching caller-supplied facts is not proof.
#[cfg(any(windows, test))]
fn require_safe_media_target() -> Result<()> {
    Err(CoreError::MediaExecutorNotReady)
}

#[cfg(any(windows, test))]
pub struct WindowsAdkExecutor {
    /// MakeWinPEMedia /UFD destination, e.g. "F:". It is supplied
    /// independently of the plan and is not yet bound to the target.
    target_spec: String,
    /// ADK install root. The default is the documented install
    /// location for the Windows ADK.
    adk_root: std::path::PathBuf,
    /// copype working directory (created fresh per build).
    work_dir: std::path::PathBuf,
}

#[cfg(any(windows, test))]
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

#[cfg(any(windows, test))]
fn rel_path(rel: &str) -> std::path::PathBuf {
    rel.split('/').collect()
}

#[cfg(any(windows, test))]
impl MediaExecutor for WindowsAdkExecutor {
    fn execute(&self, plan: &MediaPlan, progress: &mut dyn FnMut(u64, u64)) -> Result<()> {
        // This must precede the environment gate, command execution,
        // working-directory writes, and media-manifest publication.
        require_safe_media_target()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::{
        plan_media, MediaFacts, MediaPlanOptions, MediaTargetFacts, WinPeSourceFacts,
    };
    use std::fs;
    use std::process::Command;

    fn harmless_plan() -> MediaPlan {
        let facts = MediaFacts {
            target: MediaTargetFacts {
                disk_id: "synthetic-disk".into(),
                model: "test device".into(),
                serial_suffix: "1234".into(),
                size_bytes: 16 * 1024 * 1024 * 1024,
                removable: true,
            },
            winpe: WinPeSourceFacts {
                wim_path: "not-a-real-wim".into(),
                wim_size_bytes: 4096,
                present: true,
                adk_version: None,
            },
            drivers: vec![],
            payload: vec![],
        };
        let mut plan = plan_media(&facts, &MediaPlanOptions::default()).unwrap();
        // Even if the fence regresses, this test never supplies a
        // MakeMedia step or a real device selector.
        plan.steps = vec![MediaStep::Copype {
            arch: "amd64".into(),
        }];
        plan
    }

    fn assert_executor_is_inert() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "safereturn-media-fence-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&base).unwrap();
        let sentinel = base.join("sentinel.txt");
        fs::write(&sentinel, b"unchanged").unwrap();
        let work = base.join("work");
        let mut executor = WindowsAdkExecutor::new(base.join("not-a-drive").display().to_string())
            .with_adk_root(base.join("missing-adk"));
        executor.work_dir = work.clone();
        let mut progress_calls = 0;
        let err = executor
            .execute(&harmless_plan(), &mut |_, _| progress_calls += 1)
            .unwrap_err();
        assert!(matches!(err, CoreError::MediaExecutorNotReady));
        assert_eq!(err.code(), "media.executor_not_ready");
        assert!(err.to_string().contains("does not enable media creation"));
        assert_eq!(progress_calls, 0);
        assert!(
            !work.exists(),
            "the executor must not prepare working files"
        );
        assert_eq!(fs::read(sentinel).unwrap(), b"unchanged");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn adk_executor_refuses_even_when_live_is_enabled() {
        const CHILD: &str = "SAFERETURN_TEST_MEDIA_FENCE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert_executor_is_inert();
            return;
        }

        // Isolate environment changes from parallel tests. Exercise the
        // actual built-in executor both without the flag and with the
        // legacy opt-in set, using only a synthetic non-destructive plan.
        for enabled in [false, true] {
            let mut child = Command::new(std::env::current_exe().unwrap());
            child
                .arg("--exact")
                .arg("media_exec::tests::adk_executor_refuses_even_when_live_is_enabled")
                .arg("--nocapture")
                .env(CHILD, "1");
            if enabled {
                child.env(MEDIA_LIVE_ENV, "1");
            } else {
                child.env_remove(MEDIA_LIVE_ENV);
            }
            let output = child.output().unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success() && stdout.contains("1 passed;"),
                "fence test with live={enabled} failed or did not run:\n{stdout}\n{stderr}"
            );
        }
    }
}
