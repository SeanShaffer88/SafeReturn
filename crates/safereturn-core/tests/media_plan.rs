//! S4 slice 1: media-plan layout math and refusals. Expected values
//! below are computed by hand from the formula stated in media.rs
//! (content + 25% margin, 512 MiB boot floor, 1 MiB alignment,
//! data = target − 1 MiB − boot), not copied from the implementation.

use safereturn_core::media::*;
use safereturn_core::CoreError;

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

fn facts(target_bytes: u64, wim_bytes: u64, payload_bytes: u64) -> MediaFacts {
    MediaFacts {
        target: MediaTargetFacts {
            disk_id: "disk-3".into(),
            model: "USB Flash Drive".into(),
            serial_suffix: "X7K2".into(),
            size_bytes: target_bytes,
            removable: true,
        },
        winpe: WinPeSourceFacts {
            wim_path: "C:\\WinPE_amd64\\media\\sources\\boot.wim".into(),
            wim_size_bytes: wim_bytes,
            present: true,
            adk_version: Some("10.1.26100.2454".into()),
        },
        drivers: vec!["C:\\drivers\\nvme.inf".into()],
        payload: if payload_bytes == 0 {
            vec![]
        } else {
            vec![PayloadFact {
                source_path: "C:\\app\\safereturn-pe.exe".into(),
                dest_rel: "safereturn/safereturn-pe.exe".into(),
                size_bytes: payload_bytes,
                sha256: "a".repeat(64),
            }]
        },
    }
}

#[test]
fn layout_math_matches_hand_computed_values() {
    // content = 400 MiB + 50 MiB = 450 MiB; margin = ceil(450/4) =
    // 112.5 MiB → needed 562.5 MiB → align_up to 563 MiB.
    let plan = plan_media(&facts(16 * GIB, 400 * MIB, 50 * MIB), &Default::default()).unwrap();
    assert_eq!(plan.layout.boot_offset_bytes, MIB);
    assert_eq!(plan.layout.boot_partition_bytes, 563 * MIB);
    assert_eq!(plan.layout.data_partition_bytes, 16 * GIB - MIB - 563 * MIB);
    assert_eq!(plan.payload_total_bytes, 50 * MIB);
    assert!(plan.warnings.is_empty());
    assert!(!plan.override_non_removable);
}

#[test]
fn boot_partition_floor_applies_to_small_images() {
    // content = 100 MiB → needed 125 MiB < 512 MiB floor → boot = 512 MiB.
    let plan = plan_media(&facts(8 * GIB, 100 * MIB, 0), &Default::default()).unwrap();
    assert_eq!(plan.layout.boot_partition_bytes, 512 * MIB);
    assert_eq!(plan.layout.data_partition_bytes, 8 * GIB - MIB - 512 * MIB);
}

#[test]
fn plan_id_is_deterministic_and_content_sensitive() {
    let a = plan_media(&facts(16 * GIB, 400 * MIB, 50 * MIB), &Default::default()).unwrap();
    let b = plan_media(&facts(16 * GIB, 400 * MIB, 50 * MIB), &Default::default()).unwrap();
    assert_eq!(a.plan_id, b.plan_id);
    assert_eq!(a.plan_id.len(), 64);
    let c = plan_media(&facts(32 * GIB, 400 * MIB, 50 * MIB), &Default::default()).unwrap();
    assert_ne!(a.plan_id, c.plan_id);
}

#[test]
fn steps_are_in_build_order_with_all_components_and_drivers() {
    let plan = plan_media(&facts(16 * GIB, 400 * MIB, 50 * MIB), &Default::default()).unwrap();
    let kinds: Vec<String> = plan
        .steps
        .iter()
        .map(|s| {
            format!("{s:?}")
                .split([' ', '('])
                .next()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(kinds.first().map(String::as_str), Some("Copype"));
    assert_eq!(kinds.last().map(String::as_str), Some("MakeMedia"));
    // Optional components appear exactly once, in the documented order.
    let oc_positions: Vec<usize> = WINPE_OPTIONAL_COMPONENTS
        .iter()
        .map(|name| {
            plan.steps
                .iter()
                .position(|s| matches!(s, MediaStep::AddOptionalComponent { name: n } if n == name))
                .unwrap_or_else(|| panic!("missing OC step {name}"))
        })
        .collect();
    assert!(
        oc_positions.windows(2).all(|w| w[0] < w[1]),
        "OC steps out of dependency order: {oc_positions:?}"
    );
    assert!(plan
        .steps
        .iter()
        .any(|s| matches!(s, MediaStep::AddDriver { inf_path } if inf_path.ends_with("nvme.inf"))));
    // MakeMedia always carries bootex (UEFI CA 2023), per the plan.
    assert!(matches!(
        plan.steps.last(),
        Some(MediaStep::MakeMedia { bootex: true })
    ));
    // Unmount/commit comes after all servicing, before MakeMedia.
    let unmount = plan
        .steps
        .iter()
        .position(|s| matches!(s, MediaStep::UnmountAndCommit))
        .unwrap();
    assert!(unmount > *oc_positions.last().unwrap());
    assert_eq!(plan.optional_components.len(), 6);
}

#[test]
fn refuses_target_under_8_gib() {
    let err = plan_media(&facts(4 * GIB, 100 * MIB, 0), &Default::default()).unwrap_err();
    assert!(matches!(
        err,
        CoreError::MediaTargetTooSmall {
            size_bytes,
            min_bytes
        } if size_bytes == 4 * GIB && min_bytes == MIN_TARGET_BYTES
    ));
    assert_eq!(err.code(), "media.target_too_small");
}

#[test]
fn refuses_non_removable_without_override_and_warns_with_it() {
    let mut f = facts(16 * GIB, 100 * MIB, 0);
    f.target.removable = false;
    let err = plan_media(&f, &Default::default()).unwrap_err();
    assert!(matches!(err, CoreError::MediaTargetNotRemovable));
    assert_eq!(err.code(), "media.target_not_removable");

    let plan = plan_media(
        &f,
        &MediaPlanOptions {
            allow_non_removable: true,
        },
    )
    .unwrap();
    assert_eq!(plan.warnings, vec![MediaWarning::NonRemovableOverride]);
    assert!(plan.override_non_removable);
    assert_eq!(
        MediaWarning::NonRemovableOverride.id(),
        "media.target_not_removable_override"
    );
    // The override is part of the confirmed facts ⇒ a different plan id.
    let removable_plan = plan_media(&facts(16 * GIB, 100 * MIB, 0), &Default::default()).unwrap();
    assert_ne!(plan.plan_id, removable_plan.plan_id);
}

#[test]
fn refuses_missing_winpe_source() {
    let mut f = facts(16 * GIB, 100 * MIB, 0);
    f.winpe.present = false;
    let err = plan_media(&f, &Default::default()).unwrap_err();
    assert!(matches!(err, CoreError::MediaSourceMissing { .. }));
    assert_eq!(err.code(), "media.winpe_source_missing");

    let mut f2 = facts(16 * GIB, 0, 0);
    f2.winpe.present = true;
    let err2 = plan_media(&f2, &Default::default()).unwrap_err();
    assert!(matches!(err2, CoreError::MediaSourceMissing { .. }));
}

#[test]
fn refuses_payload_that_breaks_the_fat32_ceiling() {
    // 40 GiB wim alone: needed = 50 GiB > 32 GiB FAT32 ceiling.
    let err = plan_media(&facts(128 * GIB, 40 * GIB, 0), &Default::default()).unwrap_err();
    assert!(matches!(
        err,
        CoreError::MediaPayloadTooLarge {
            needed_bytes,
            available_bytes
        } if needed_bytes == 50 * GIB && available_bytes == FAT32_MAX_BYTES
    ));
    assert_eq!(err.code(), "media.payload_too_large");
}

#[test]
fn refuses_when_no_room_for_data_partition() {
    // Exactly-8 GiB target with a wim sized so boot eats the disk:
    // wim 6.5 GiB → needed 8.125 GiB > what fits with a data side.
    let err = plan_media(&facts(8 * GIB, 6 * GIB + 512 * MIB, 0), &Default::default()).unwrap_err();
    assert!(matches!(err, CoreError::MediaPayloadTooLarge { .. }));
}

#[test]
fn refuses_malformed_facts() {
    let mut f = facts(16 * GIB, 100 * MIB, 0);
    f.target.serial_suffix = "ABC".into();
    assert!(matches!(
        plan_media(&f, &Default::default()).unwrap_err(),
        CoreError::MediaInvalidFacts { .. }
    ));

    let mut f = facts(16 * GIB, 100 * MIB, 1);
    f.payload[0].dest_rel = "../evil.exe".into();
    assert!(matches!(
        plan_media(&f, &Default::default()).unwrap_err(),
        CoreError::MediaInvalidFacts { .. }
    ));

    let mut f = facts(16 * GIB, 100 * MIB, 1);
    f.payload[0].dest_rel = "/abs/path.exe".into();
    assert!(matches!(
        plan_media(&f, &Default::default()).unwrap_err(),
        CoreError::MediaInvalidFacts { .. }
    ));

    let mut f = facts(16 * GIB, 100 * MIB, 0);
    f.drivers = vec!["  ".into()];
    assert!(matches!(
        plan_media(&f, &Default::default()).unwrap_err(),
        CoreError::MediaInvalidFacts { .. }
    ));
}
