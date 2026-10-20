//! Golden-fixture tests: serialize one representative of each wire message,
//! compare with ../golden/*.json, and round-trip back to the same value.
//! Regenerate fixtures with SR_UPDATE_GOLDEN=1 cargo test.
//! The C# shell's test suite deserializes these exact files (SHELL_CONTRACT §2.4).

use safereturn_contract::*;
use std::fs;
use std::path::PathBuf;

fn fixtures() -> Vec<(&'static str, WireMessage)> {
    vec![
        (
            "hello",
            WireMessage::Request {
                id: 1,
                body: Request::Hello {
                    contract_version: CONTRACT_VERSION,
                    shell: ShellKind::WinUiDesktop,
                    shell_version: "0.1.0".into(),
                },
            },
        ),
        (
            "disk_list",
            WireMessage::Event(Event::DiskList {
                disks: vec![DiskInfo {
                    disk_id: "disk-2".into(),
                    model: "Seagate Backup Plus".into(),
                    serial_suffix: "X7K2".into(),
                    size_bytes: 2_000_000_000_000,
                    free_bytes: 1_800_000_000_000,
                    is_system_disk: false,
                    is_removable: true,
                    warnings: vec![],
                }],
            }),
        ),
        (
            "backup_planned",
            WireMessage::Event(Event::BackupPlanned(BackupPlan {
                destination_disk_id: "disk-2".into(),
                estimated_backup_bytes: 240_000_000_000,
                destination_free_bytes: 1_800_000_000_000,
                verdict: SpaceVerdict::Fits,
                summary_line_ids: vec!["plan.will_copy_everything".into()],
            })),
        ),
        (
            "job_progress",
            WireMessage::Event(Event::JobProgress {
                job_id: "job-1".into(),
                phase_id: "phase.copying_files".into(),
                done: 42,
                total: 100,
                unit: "files".into(),
            }),
        ),
        (
            "plan_restore",
            WireMessage::Request {
                id: 7,
                body: Request::PlanRestore {
                    backup_id: "1700000100-first-a1b2c3d4".into(),
                    target_dir: "C:\\Users\\Sam\\Restored".into(),
                    path: None,
                },
            },
        ),
        (
            "start_restore",
            WireMessage::Request {
                id: 8,
                body: Request::StartRestore {
                    plan_token:
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                },
            },
        ),
        (
            "backup_list",
            WireMessage::Event(Event::BackupList {
                backups: vec![BackupSummary {
                    backup_id: "1700000100-first-a1b2c3d4".into(),
                    label: "First backup".into(),
                    created_unix: 1700000100,
                    file_count: 128,
                    total_bytes: 4_200_000_000,
                }],
            }),
        ),
        (
            "restore_planned",
            WireMessage::Event(Event::RestorePlanned(RestorePlan {
                plan_token:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                backup_id: "1700000100-first-a1b2c3d4".into(),
                target_summary:
                    "128 files (4.2 GB) to C:\\Users\\Sam\\Restored — 2 existing files will be replaced"
                        .into(),
                erase_warning_id: Some("restore.will_overwrite_files".into()),
                file_count: 128,
                total_bytes: 4_200_000_000,
                overwrite_count: 2,
            })),
        ),
        (
            "plan_media",
            WireMessage::Request {
                id: 9,
                body: Request::PlanMedia {
                    target_disk_id: "disk-2".into(),
                },
            },
        ),
        (
            "create_media",
            WireMessage::Request {
                id: 10,
                body: Request::CreateMedia {
                    plan_token:
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                },
            },
        ),
        (
            "media_planned",
            WireMessage::Event(Event::MediaPlanned(MediaPlan {
                plan_token:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                target_disk_id: "disk-2".into(),
                target_summary:
                    "Seagate Backup Plus (…X7K2): 16.0 GB device — 590.3 MB boot (FAT32), 15.4 GB data (NTFS)"
                        .into(),
                erase_warning_id: Some("media.will_erase_target".into()),
                boot_partition_bytes: 590_348_288,
                data_partition_bytes: 16_588_472_320,
                payload_bytes: 52_428_800,
                warnings: vec![],
            })),
        ),
        (
            "plan_system_restore",
            WireMessage::Request {
                id: 11,
                body: Request::PlanSystemRestore {
                    backup_id: "1700000100-first-a1b2c3d4".into(),
                    target_disk_id: "disk-2".into(),
                },
            },
        ),
        (
            "start_system_restore",
            WireMessage::Request {
                id: 12,
                body: Request::StartSystemRestore {
                    plan_token:
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                },
            },
        ),
        (
            "system_restore_planned",
            WireMessage::Event(Event::SystemRestorePlanned(SystemRestorePlan {
                plan_token:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                backup_id: "1700000100-first-a1b2c3d4".into(),
                target_disk_id: "disk-2".into(),
                target_summary:
                    "Seagate Backup Plus (…X7K2): 2.0 TB disk — 4 partitions (GPT, UEFI), 128 files, 240.0 GB to restore"
                        .into(),
                erase_warning_id: Some("system_restore.will_erase_target".into()),
                firmware: "uefi".into(),
                partition_count: 4,
                file_count: 128,
                total_bytes: 240_000_000_000,
                warnings: vec!["system_restore.winre_missing".into()],
            })),
        ),
        (
            "job_finished_failed",
            WireMessage::Event(Event::JobFinished {
                job_id: "job-1".into(),
                outcome: JobOutcome::Failed,
                summary_id: "result.backup_failed_writer".into(),
            }),
        ),
        (
            "error",
            WireMessage::Event(Event::Error {
                code: "vss.writer_failed".into(),
                message_id: "error.vss_writer_failed".into(),
                what_was_not_changed_id: "error.nothing_changed".into(),
            }),
        ),
    ]
}

#[test]
fn golden_fixtures_match_and_roundtrip() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("golden");
    let update = std::env::var_os("SR_UPDATE_GOLDEN").is_some();
    for (name, msg) in fixtures() {
        let json = serde_json::to_string_pretty(&msg).unwrap();
        let path = dir.join(format!("{name}.json"));
        if update {
            fs::write(&path, &json).unwrap();
        } else {
            let expected = fs::read_to_string(&path)
                .unwrap_or_else(|_| {
                    panic!("missing golden fixture {name}.json — run with SR_UPDATE_GOLDEN=1")
                })
                // A checkout that converted line endings (CRLF) is not
                // drift — the repo pins LF via .gitattributes, and this
                // normalization keeps older clones honest too. (CI run
                // #2 failed on exactly this: identical JSON, CRLF file.)
                .replace("\r\n", "\n");
            assert_eq!(expected, json, "golden fixture {name} drifted — if this change is intentional, regenerate and update the C# DTOs");
        }
        let back: WireMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, msg, "{name} did not round-trip");
    }
}
