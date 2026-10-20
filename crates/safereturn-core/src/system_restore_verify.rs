//! System-restore verification (S5, slice 3): re-read an applied
//! tree (real disk staging area or the simulation's fake disk) and
//! check it against the plan that produced it.
//!
//! The central honesty rule of this module: **"files in place" is
//! not "boot registered".** Verification can prove every file the
//! plan called for is present with the right content, the ESP
//! carries the required boot files, and the WinRE image is where
//! the plan put it. It cannot prove the BCD store points at the
//! restored Windows or that firmware will boot the disk — that is
//! created by bcdboot/reagentc on the machine and confirmed by an
//! actual boot. So `boot_files_registered` is a sourced Fact that
//! this function ALWAYS returns as unknown-with-a-reason. Only the
//! on-machine flow may ever set it, from the tools' own results.
//! A report whose files all check out and whose registration is
//! unverified is a truthful report; conflating the two is how a
//! "successful" restore turns out to be an unbootable disk.

use crate::error::Result;
use crate::sets::hash_existing_file;
use crate::system::Fact;
use crate::system_restore::{PartitionRole, SystemRestorePlan, WINRE_IMAGE_DEST_REL};
use crate::system_restore_exec::dest_path;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Per-partition outcome of re-reading the applied tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionVerify {
    pub role: PartitionRole,
    pub files_checked: u64,
    pub files_ok: u64,
    /// Destination paths (inside the partition) that are absent.
    pub missing: Vec<String>,
    /// Destination paths whose content hash differs from the plan.
    pub mismatched: Vec<String>,
}

impl PartitionVerify {
    pub fn passed(&self) -> bool {
        self.missing.is_empty() && self.mismatched.is_empty()
    }
}

/// One required ESP boot file and whether it is present in the
/// applied ESP (named after media_verify's BootFileCheck, kept a
/// separate type because that one carries no serde derives).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EspBootFileCheck {
    /// Path inside the ESP, as the plan names it.
    pub path: String,
    pub present: bool,
}

/// The verification report for one applied plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemRestoreVerifyReport {
    pub plan_id: String,
    pub set_id: String,
    /// One entry per layout partition, in layout order (the MSR
    /// checks zero files — it holds none by design).
    pub partitions: Vec<PartitionVerify>,
    /// The plan's required ESP boot files and whether each is
    /// present in the applied ESP.
    pub esp_boot_files: Vec<EspBootFileCheck>,
    /// Whether the WinRE image is present where the plan placed it.
    /// `None` when the plan included no WinRE (a disclosed gap —
    /// its absence here is not a failure of the restore).
    pub winre_image_present: Option<bool>,
    /// Whether the boot files were REGISTERED (BCD store created
    /// by bcdboot, WinRE registered by reagentc) — as opposed to
    /// merely present. Always unknown from file inspection; see the
    /// module docs. Only the on-machine flow sets this, from the
    /// tools' own exit results.
    pub boot_files_registered: Fact<bool>,
}

impl SystemRestoreVerifyReport {
    /// Everything verification can prove from the files: every
    /// planned file present with matching content, the required
    /// ESP boot files present, and the WinRE image present iff the
    /// plan placed one. Deliberately says nothing about boot
    /// registration — see `boot_files_registered`.
    pub fn files_in_place(&self) -> bool {
        self.partitions.iter().all(|p| p.passed())
            && self.esp_boot_files.iter().all(|b| b.present)
            && self.winre_image_present != Some(false)
    }
}

/// Re-read the applied tree at `applied_root` (partition
/// directories named by `PartitionRole::dir_name`, exactly as the
/// simulation executor lays them out and as the on-machine staging
/// does) and check it against `plan`.
pub fn verify_system_restore(
    plan: &SystemRestorePlan,
    applied_root: &Path,
) -> Result<SystemRestoreVerifyReport> {
    let mut partitions: Vec<PartitionVerify> = plan
        .layout
        .iter()
        .map(|spec| PartitionVerify {
            role: spec.role,
            files_checked: 0,
            files_ok: 0,
            missing: Vec::new(),
            mismatched: Vec::new(),
        })
        .collect();

    for step in &plan.applications {
        let path = dest_path(
            &applied_root.join(step.partition.dir_name()),
            &step.dest_rel,
        );
        let pv = partitions
            .iter_mut()
            .find(|p| p.role == step.partition)
            .expect("every application targets a layout partition");
        pv.files_checked += 1;
        match hash_existing_file(&path)? {
            None => pv.missing.push(step.dest_rel.clone()),
            Some(h) if h == step.sha256 => pv.files_ok += 1,
            Some(_) => pv.mismatched.push(step.dest_rel.clone()),
        }
    }

    // Required boot files: resolve each through the plan's ESP
    // applications (case-insensitively, as FAT32 would), then check
    // presence on disk.
    let mut esp_boot_files = Vec::new();
    for required in &plan.required_boot_files {
        let applied = plan
            .applications
            .iter()
            .find(|a| {
                a.partition == PartitionRole::Esp && a.dest_rel.eq_ignore_ascii_case(required)
            })
            .map(|a| {
                dest_path(
                    &applied_root.join(PartitionRole::Esp.dir_name()),
                    &a.dest_rel,
                )
                .exists()
            })
            .unwrap_or(false);
        esp_boot_files.push(EspBootFileCheck {
            path: required.clone(),
            present: applied,
        });
    }

    let winre_image_present = if plan.partition(PartitionRole::WinRe).is_some() {
        Some(
            dest_path(
                &applied_root.join(PartitionRole::WinRe.dir_name()),
                WINRE_IMAGE_DEST_REL,
            )
            .exists(),
        )
    } else {
        None
    };

    Ok(SystemRestoreVerifyReport {
        plan_id: plan.plan_id.clone(),
        set_id: plan.set_id.clone(),
        partitions,
        esp_boot_files,
        winre_image_present,
        boot_files_registered: Fact::unknown(
            "verify_system_restore: file inspection of the applied tree",
            "boot registration is created by bcdboot and reagentc on the target machine and cannot be concluded from files being present. On a simulated restore those commands were recorded, not run. This fact is set only by the on-machine flow, from the tools' own results.",
        ),
    })
}
