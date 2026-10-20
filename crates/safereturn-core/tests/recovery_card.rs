//! S6 slice 5: the Recovery Card.
//! - Required sections in both formats.
//! - The password rule: the fixed no-password line is always
//!   present; the hint is a LOCATION line and renders verbatim
//!   (spaces, long random text — under its label, escaped in HTML).
//!   The API has no passphrase parameter by construction — the
//!   facts struct is the whole API surface these tests exercise.
//! - The boot-key rule: a stated key renders as this PC's key and
//!   the guidance table does NOT appear; an unknown key renders
//!   the guidance table, labelled as guidance.
//! - Unusable facts refuse with the typed error.

use safereturn_core::recovery_card::*;
use safereturn_core::CoreError;

fn facts() -> RecoveryCardFacts {
    RecoveryCardFacts {
        pc_description: "Sean's desktop PC (office)".to_string(),
        backup_drive: DriveIdentification {
            model: "WD Elements 2621".to_string(),
            serial_suffix: "7K2P".to_string(),
            label: Some("BACKUPS-BLUE".to_string()),
        },
        media: Some(DriveIdentification {
            model: "SanDisk Ultra USB 3.0".to_string(),
            serial_suffix: "4410".to_string(),
            label: None,
        }),
        boot_menu_key: Some("F12".to_string()),
        password_hint_location: Some("in the fire safe in the office closet".to_string()),
        last_backup: Some(LastBackupFact {
            label: "Weekly backup".to_string(),
            set_id: "set-2026-10-18".to_string(),
            created_unix: 1_700_003_000,
            file_count: 12_345,
            total_bytes: 42_000_000_000,
        }),
        last_rehearsal: Some(LastRehearsalFact {
            level_label: "Level 3 — Boot Rehearsal".to_string(),
            unix: 1_700_100_000,
            summary: "files verified; not boot-tested".to_string(),
        }),
        generated_unix: 1_700_200_000,
        app_version: "0.6.0-test".to_string(),
    }
}

#[test]
fn both_formats_have_every_required_section() {
    let text = render_card_text(&facts()).unwrap();
    for needle in [
        "SAFERETURN RECOVERY CARD",
        "Sean's desktop PC (office)",
        "WD Elements 2621",
        "serial ends 7K2P",
        "BACKUPS-BLUE",
        "SanDisk Ultra USB 3.0",
        "TO GET FILES BACK",
        "TO BRING THE WHOLE PC BACK",
        "1. ",
        "2. ",
        "3. ",
        NO_PASSWORD_LINE,
        "Where it is kept (a location, written by you): in the fire safe in the office closet",
        "Last backup:",
        "Weekly backup",
        "Last rehearsal: Level 3 — Boot Rehearsal",
        "Backup ID: set-2026-10-18",
        "SafeReturn 0.6.0-test",
        "2023-11", // generated date rendered (unix 1700200000 → 2023-11)
    ] {
        assert!(
            text.contains(needle),
            "text card missing {needle:?}\n{text}"
        );
    }

    let html = render_card_html(&facts()).unwrap();
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("<html lang=\"en\">"));
    assert!(html.contains("SafeReturn Recovery Card"));
    for needle in [
        "WD Elements 2621",
        "serial ends 7K2P",
        "To get files back",
        "To bring the whole PC back",
        NO_PASSWORD_LINE,
        "in the fire safe in the office closet",
        "Level 3 — Boot Rehearsal",
        "set-2026-10-18",
    ] {
        assert!(html.contains(needle), "html card missing {needle:?}");
    }
    // Standalone: no external resources.
    assert!(
        !html.contains("http://") && !html.contains("https://"),
        "card must be standalone"
    );
    assert!(!html.contains("<script"), "card must be inert");
}

#[test]
fn stated_boot_key_replaces_the_guidance_table() {
    let text = render_card_text(&facts()).unwrap();
    assert!(text.contains("This PC's boot-menu key: F12"));
    assert!(
        !text.contains("Common keys by maker"),
        "guidance must not appear when the key is known"
    );
    let html = render_card_html(&facts()).unwrap();
    assert!(html.contains("This PC's boot-menu key:"));
    assert!(!html.contains("<table>"));

    // Unknown: the table appears, labelled as guidance.
    let mut unknown = facts();
    unknown.boot_menu_key = None;
    let text = render_card_text(&unknown).unwrap();
    assert!(text.contains("is not recorded"));
    assert!(text.contains("general guidance"));
    for (vendor, _key) in BOOT_KEY_GUIDANCE {
        assert!(text.contains(vendor), "guidance missing {vendor}");
    }
    let html = render_card_html(&unknown).unwrap();
    assert!(html.contains("<table>"));
    assert!(html.contains("general guidance"));
}

#[test]
fn hint_is_a_verbatim_location_line_never_a_secret_slot() {
    // A long, space-containing, password-LOOKING string still
    // renders verbatim as the location line under its label: the
    // API's contract is "this field is where the password lives,
    // in words", and the no-password line is always right there.
    let mut f = facts();
    let location_text = "correct horse battery staple — written on the card inside the blue folder, drawer 2, behind the tax files";
    f.password_hint_location = Some(location_text.to_string());
    let text = render_card_text(&f).unwrap();
    assert!(text.contains(&format!(
        "Where it is kept (a location, written by you): {location_text}"
    )));
    assert!(text.contains(NO_PASSWORD_LINE));
    let html = render_card_html(&f).unwrap();
    assert!(html.contains("Where it is kept (a location, written by you):"));
    assert!(html.contains(NO_PASSWORD_LINE));

    // No hint at all: a blank to fill in by hand, still with the
    // no-password line — and still clearly a LOCATION prompt.
    let mut f = facts();
    f.password_hint_location = None;
    let text = render_card_text(&f).unwrap();
    assert!(text.contains("Write the LOCATION here by hand"));
    assert!(text.contains(NO_PASSWORD_LINE));

    // HTML: a markup-bearing location is escaped, not injected.
    let mut f = facts();
    f.password_hint_location = Some("<script>alert(1)</script> drawer".to_string());
    let html = render_card_html(&f).unwrap();
    assert!(!html.contains("<script>alert"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt; drawer"));
}

#[test]
fn no_rehearsal_yet_says_not_tested_never_invents_one() {
    let mut f = facts();
    f.last_rehearsal = None;
    let text = render_card_text(&f).unwrap();
    assert!(text.contains("NOT TESTED YET"));
    assert!(text.contains("Test your recovery"));
    let mut f = facts();
    f.last_backup = None;
    let text = render_card_text(&f).unwrap();
    assert!(text.contains("Last backup: none recorded"));
}

#[test]
fn unusable_facts_refuse_with_the_typed_error() {
    let mut f = facts();
    f.pc_description = "  ".to_string();
    assert!(matches!(
        render_card_text(&f),
        Err(CoreError::RecoveryCardInvalidFacts { .. })
    ));
    let mut f = facts();
    f.backup_drive.serial_suffix = "7K2".to_string(); // 3 chars
    assert!(matches!(
        render_card_text(&f),
        Err(CoreError::RecoveryCardInvalidFacts { .. })
    ));
    let mut f = facts();
    f.backup_drive.serial_suffix = "FULLSERIAL1234".to_string();
    assert!(matches!(
        render_card_html(&f),
        Err(CoreError::RecoveryCardInvalidFacts { .. })
    ));
    let mut f = facts();
    f.boot_menu_key = Some("".to_string());
    assert!(matches!(
        render_card_text(&f),
        Err(CoreError::RecoveryCardInvalidFacts { .. })
    ));
}
