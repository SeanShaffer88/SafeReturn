//! The WinPE recovery shell's in-process engine transport (S6,
//! slice 3) plus the shell binary's platform-agnostic support.
//!
//! ## Why in-process transport
//!
//! SHELL_CONTRACT §3: on the desktop, shells talk to the engine
//! over a named pipe because the engine is a separate, elevated
//! process. In WinPE there is no service host and no second
//! process to pipe to — the recovery shell *is* the process, booted
//! from the media, already elevated by definition. So the PE shell
//! calls the engine library directly. **The contract boundary is
//! the message types, not the transport**: this adapter accepts
//! contract `Request`s and returns contract `Event`s, exactly what
//! the desktop pipe carries, so the view-model in
//! `safereturn-shell` cannot tell which transport it is on, and the
//! two transports stay interchangeable.
//!
//! ## What the adapter owns (host glue, not decisions)
//!
//! - Disk enumeration results (via `DiskSource`, supplied by the
//!   platform layer) and the target facts built from them.
//! - The set-root → partition mapping for whole-PC restores,
//!   derived from the set manifest's own contents (see
//!   `derive_root_mapping`) — the engine never guesses, and neither
//!   does the shell: the derivation is stated, deterministic, and
//!   refuses when it cannot be made.
//! - The SafeTarget context for guarded planning, including the
//!   warning acknowledgments the user confirms in the plan flow
//!   (the view-model reports them as `ShellEffect`s; the front-end
//!   calls `acknowledge_warning` here before the retried plan
//!   request is handled).
//! - Error translation: engine `CoreError`s become contract
//!   `Event::Error`s with the contract's honesty fields.

use safereturn_contract::{DiskInfo, Event, Request, CONTRACT_VERSION};
use safereturn_core::{
    BootMode, CoreError, Engine, Fact, SafeTargetContext, SetManifest, SystemRestoreExecutor,
    SystemRestoreOptions, SystemRestoreTargetFacts,
};
use std::path::PathBuf;

#[cfg(windows)]
pub mod win32;
#[cfg(windows)]
pub mod win32_bindings;
#[cfg(windows)]
pub mod win32_disks;

/// Disk enumeration, supplied by the platform layer. The recovery
/// shell's Win32 implementation is in `win32_disks` (cfg(windows));
/// tests supply fakes.
pub trait DiskSource {
    fn list_disks(&self) -> Vec<DiskInfo>;
    /// The OS disk index (PhysicalDrive number) for executor
    /// construction, when the source knows it.
    fn disk_index(&self, _disk_id: &str) -> Option<u32> {
        None
    }
}

/// How system restores are executed. `Fixed` is the simulation /
/// test path (an explicit caller choice, as everywhere in the
/// engine); `Platform` builds the platform executor per target
/// disk at execute time — on Windows that is the gated S5 skeleton,
/// which renders its artifacts and refuses to run them.
pub enum ExecutorChoice {
    Fixed(Box<dyn SystemRestoreExecutor>),
    Platform { work_dir: PathBuf },
}

/// The `what_was_not_changed_id` every adapter error carries: the
/// adapter translates errors from operations that, on failure,
/// changed nothing the user cares about (planning, listing) or
/// that the engine itself guarantees left the target untouched
/// (its plan-token refusals fire before any executor runs).
pub const NOTHING_CHANGED_ID: &str = "shell.error.nothing_changed";

/// Translate an engine error into the contract error event.
/// SafeTarget errors carry their reason/warning id as the message
/// id (that id IS the strings-table entry the shell renders);
/// everything else renders by its stable code.
pub fn error_event(err: &CoreError) -> Event {
    let message_id = match err {
        CoreError::SafeTargetRefused { reason_id, .. } => reason_id.clone(),
        CoreError::SafeTargetOverrideRequired { warning_id, .. } => warning_id.clone(),
        other => other.code().to_string(),
    };
    Event::Error {
        code: err.code().to_string(),
        message_id,
        what_was_not_changed_id: NOTHING_CHANGED_ID.to_string(),
    }
}

fn unsupported_event() -> Event {
    Event::Error {
        code: "shell.unsupported_in_pe".to_string(),
        message_id: "shell.error.unsupported".to_string(),
        what_was_not_changed_id: NOTHING_CHANGED_ID.to_string(),
    }
}

/// Derive the OS/ESP root mapping for a whole-PC restore from the
/// set manifest itself: the ESP root is the recorded root whose
/// files include both required UEFI boot files (compared
/// case-insensitively, as the S5 planner compares them); the OS
/// root is the other root when the set has exactly two. Anything
/// else refuses with the planner's invalid-facts error — a mapping
/// is derived from evidence or not at all.
pub fn derive_root_mapping(manifest: &SetManifest) -> Result<SystemRestoreOptions, CoreError> {
    let has_boot_files = |root: &str| {
        let prefix = format!("{root}/");
        let mut mgfw = false;
        let mut x64 = false;
        for f in &manifest.files {
            if let Some(rel) = f.path.strip_prefix(&prefix) {
                let rel = rel.to_lowercase();
                if rel == "efi/microsoft/boot/bootmgfw.efi" {
                    mgfw = true;
                }
                if rel == "efi/boot/bootx64.efi" {
                    x64 = true;
                }
            }
        }
        mgfw && x64
    };
    let esp_root = manifest.roots.iter().find(|r| has_boot_files(r)).cloned();
    match (esp_root, manifest.roots.len()) {
        (Some(esp), 2) => {
            let os = manifest
                .roots
                .iter()
                .find(|r| **r != esp)
                .expect("two roots, one is the ESP")
                .clone();
            Ok(SystemRestoreOptions {
                os_root: os,
                esp_root: esp,
            })
        }
        (Some(_), n) => Err(CoreError::SystemRestoreInvalidFacts {
            reason: format!(
                "the set records {n} roots; the recovery shell can only derive the OS/ESP mapping for a set with exactly two roots (the OS volume and the ESP). Restore this set from the desktop shell or the CLI, where the mapping is stated explicitly"
            ),
        }),
        (None, _) => Err(CoreError::SystemRestoreInvalidFacts {
            reason: "no recorded root of this set contains the EFI boot files, so the ESP capture cannot be identified from the set itself".to_string(),
        }),
    }
}

/// The in-process transport: contract requests in, contract events
/// out, engine in the middle.
pub struct EngineAdapter {
    engine: Engine,
    disk_source: Box<dyn DiskSource>,
    safe_target: SafeTargetContext,
    firmware: Fact<BootMode>,
    executors: ExecutorChoice,
    disk_cache: Vec<DiskInfo>,
    planned_target: Option<SystemRestoreTargetFacts>,
}

impl EngineAdapter {
    pub fn new(
        engine: Engine,
        disk_source: Box<dyn DiskSource>,
        safe_target: SafeTargetContext,
        firmware: Fact<BootMode>,
        executors: ExecutorChoice,
    ) -> Self {
        Self {
            engine,
            disk_source,
            safe_target,
            firmware,
            executors,
            disk_cache: Vec::new(),
            planned_target: None,
        }
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Record a SafeTarget warning acknowledgment the user
    /// confirmed in the plan flow (reported by the view-model as a
    /// `ShellEffect::AcknowledgeWarning`).
    pub fn acknowledge_warning(&mut self, warning_id: &str) {
        if !self.safe_target.acknowledges(warning_id) {
            self.safe_target
                .acknowledged_warnings
                .push(warning_id.to_string());
        }
    }

    fn refresh_disks(&mut self) -> &Vec<DiskInfo> {
        self.disk_cache = self.disk_source.list_disks();
        &self.disk_cache
    }

    fn target_facts(&self, disk: &DiskInfo) -> SystemRestoreTargetFacts {
        SystemRestoreTargetFacts {
            disk_id: disk.disk_id.clone(),
            model: disk.model.clone(),
            serial_suffix: disk.serial_suffix.clone(),
            size_bytes: disk.size_bytes,
            removable: disk.is_removable,
            firmware: self.firmware.clone(),
        }
    }

    /// Handle one contract request; returns the events it produced
    /// (possibly several for jobs, exactly one for plans/lists).
    pub fn handle(&mut self, request: Request) -> Vec<Event> {
        let mut events: Vec<Event> = Vec::new();
        match request {
            Request::Hello {
                contract_version, ..
            } => {
                if contract_version != CONTRACT_VERSION {
                    events.push(Event::Incompatible {
                        minimum_contract_version: CONTRACT_VERSION,
                    });
                } else {
                    events.push(Event::Welcome {
                        contract_version: CONTRACT_VERSION,
                        engine_version: env!("CARGO_PKG_VERSION").to_string(),
                    });
                }
            }
            Request::ListDisks => {
                let disks = self.refresh_disks().clone();
                events.push(Event::DiskList { disks });
            }
            Request::ListBackups => {
                let mut sink = |e: Event| events.push(e);
                if let Err(e) = self.engine.list_backups(&mut sink) {
                    events.push(error_event(&e));
                }
            }
            Request::PlanRestore {
                backup_id,
                target_dir,
                path,
            } => {
                let mut sink = |e: Event| events.push(e);
                if let Err(e) = self.engine.plan_restore(
                    &backup_id,
                    &PathBuf::from(target_dir),
                    path.as_deref(),
                    &mut sink,
                ) {
                    events.push(error_event(&e));
                }
            }
            Request::StartRestore { plan_token } => {
                let mut sink = |e: Event| events.push(e);
                if let Err(e) = self.engine.start_restore(&plan_token, &mut sink) {
                    events.push(error_event(&e));
                }
            }
            Request::StartFileRehearsal { backup_id, paths } => {
                let mut sink = |e: Event| events.push(e);
                if let Err(e) = self
                    .engine
                    .start_file_rehearsal(&backup_id, &paths, 8, false, &mut sink)
                {
                    events.push(error_event(&e));
                }
            }
            Request::PlanSystemRestore {
                backup_id,
                target_disk_id,
            } => {
                self.plan_system_restore(&backup_id, &target_disk_id, &mut events);
            }
            Request::StartSystemRestore { plan_token } => {
                self.start_system_restore(&plan_token, &mut events);
            }
            // Accepted, not acted on: the engine has no cancellation
            // primitive yet (true for every shell, not just this
            // one), so a job in the PE subset runs to its
            // JobFinished. Recorded as a known limitation in
            // docs/S6_NOTES.md — never faked as a cancellation.
            Request::CancelJob { .. } => {}
            // Backup creation, verification jobs, and media creation
            // are desktop flows (SHELL_CONTRACT §2.5: the PE shell is
            // a subset). Named refusal, never a silent no-op.
            Request::PlanBackup { .. }
            | Request::StartBackup { .. }
            | Request::StartVerify { .. }
            | Request::PlanMedia { .. }
            | Request::CreateMedia { .. } => {
                events.push(unsupported_event());
            }
        }
        events
    }

    fn plan_system_restore(
        &mut self,
        backup_id: &str,
        target_disk_id: &str,
        events: &mut Vec<Event>,
    ) {
        if !self.disk_cache.iter().any(|d| d.disk_id == target_disk_id) {
            self.refresh_disks();
        }
        let Some(disk) = self
            .disk_cache
            .iter()
            .find(|d| d.disk_id == target_disk_id)
            .cloned()
        else {
            events.push(Event::Error {
                code: "target.not_found".to_string(),
                message_id: "target.not_found".to_string(),
                what_was_not_changed_id: NOTHING_CHANGED_ID.to_string(),
            });
            return;
        };
        let manifest = match safereturn_core::read_set_manifest(self.engine.volume(), backup_id) {
            Ok(m) => m,
            Err(e) => {
                events.push(error_event(&e));
                return;
            }
        };
        let options = match derive_root_mapping(&manifest) {
            Ok(o) => o,
            Err(e) => {
                events.push(error_event(&e));
                return;
            }
        };
        let target = self.target_facts(&disk);
        let is_system = disk.is_system_disk;
        let mut sink = |e: Event| events.push(e);
        match self.engine.plan_system_restore_guarded(
            backup_id,
            &target,
            &options,
            &self.safe_target,
            is_system,
            &mut sink,
        ) {
            Ok(_) => {
                self.planned_target = Some(target);
            }
            Err(e) => events.push(error_event(&e)),
        }
    }

    fn start_system_restore(&mut self, plan_token: &str, events: &mut Vec<Event>) {
        // Re-derive the current facts for the planned disk: the
        // engine's drift re-check compares them against the plan,
        // so a disk swapped since planning refuses as plan_stale.
        let Some(planned) = self.planned_target.clone() else {
            events.push(error_event(&CoreError::SystemRestoreInvalidPlanToken));
            return;
        };
        self.refresh_disks();
        let current = self
            .disk_cache
            .iter()
            .find(|d| d.disk_id == planned.disk_id)
            .map(|d| self.target_facts(d))
            .unwrap_or(planned.clone());
        let mut sink = |e: Event| events.push(e);
        // Disjoint field borrows: the executor choice is read while
        // the engine is mutably borrowed — both live in this body.
        let result = match &self.executors {
            ExecutorChoice::Fixed(exec) => self
                .engine
                .execute_system_restore(plan_token, &current, &**exec, &mut sink),
            ExecutorChoice::Platform { work_dir } => {
                let index = self.disk_source.disk_index(&planned.disk_id).unwrap_or(0);
                let exec =
                    safereturn_core::platform_system_restore_executor(index, work_dir.clone());
                self.engine
                    .execute_system_restore(plan_token, &current, &*exec, &mut sink)
            }
        };
        if let Err(e) = result {
            events.push(error_event(&e));
        }
    }
}
