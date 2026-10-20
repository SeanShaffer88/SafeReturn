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
            let expected = fs::read_to_string(&path).unwrap_or_else(|_| {
                panic!("missing golden fixture {name}.json — run with SR_UPDATE_GOLDEN=1")
            });
            assert_eq!(expected, json, "golden fixture {name} drifted — if this change is intentional, regenerate and update the C# DTOs");
        }
        let back: WireMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, msg, "{name} did not round-trip");
    }
}
