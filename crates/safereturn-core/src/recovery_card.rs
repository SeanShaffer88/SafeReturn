//! The Recovery Card (S6, slice 5): one printable page that lets
//! a stressed, non-technical reader — possibly a family member
//! helping — recover the PC. Generated from facts, in two forms: a
//! standalone HTML file (prints from any browser) and plain text.
//!
//! Content (architecture plan §2): which backup drive to plug in
//! and which USB to boot from; the PC's boot-menu key when known;
//! steps 1-2-3 for both restores, in large plain language; the
//! last good backup and the last rehearsal as facts; where the
//! encryption password / recovery key is *kept*.
//!
//! ## The password rule
//!
//! The card NEVER contains a password. There is no passphrase
//! parameter anywhere in this module's API — not in the facts, not
//! in the renderers. The only password-adjacent field is
//! `password_hint_location`: user-supplied text saying WHERE the
//! password is kept ("in the fire safe", "in the password manager
//! on my phone"), rendered verbatim under a label that says it is
//! a location, next to the fixed line `NO_PASSWORD_LINE`. If a
//! user writes their actual password into that field the card will
//! print it under the location label — the API cannot detect that,
//! and does not pretend to; the label, the docs, and the fixed
//! line are the honest mitigations, and they are always present.
//!
//! ## The boot-key rule
//!
//! The boot-menu key is an INPUT fact (the user or a gatherer
//! supplies it). When it is unknown the card prints a mini-table
//! of common vendors' keys, marked as generic guidance in the
//! card's own words — never presented as this PC's detected key.

use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};

/// Printed on every card, in both formats, next to the hint field.
pub const NO_PASSWORD_LINE: &str = "This card never contains your password.";

/// A drive as a stressed reader identifies it: model, last 4 of
/// the serial, and the label they wrote on it / saw in Windows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriveIdentification {
    pub model: String,
    /// Exactly the last 4 characters of the serial.
    pub serial_suffix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// The last-good-backup facts, from the volume's catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastBackupFact {
    pub label: String,
    pub set_id: String,
    pub created_unix: u64,
    pub file_count: u64,
    pub total_bytes: u64,
}

/// The last-rehearsal facts, e.g. from a Boot Rehearsal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastRehearsalFact {
    /// "Level 2 — File Rehearsal", "Level 3 — Boot Rehearsal", …
    pub level_label: String,
    pub unix: u64,
    /// The outcome in facts ("files verified; not boot-tested").
    pub summary: String,
}

/// Everything a card is generated from. Note the deliberate shape:
/// there is no passphrase field — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCardFacts {
    /// "Sean's desktop PC" — how the reader recognizes the machine.
    pub pc_description: String,
    pub backup_drive: DriveIdentification,
    /// The recovery USB, when one has been made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<DriveIdentification>,
    /// The PC's boot-menu key as an INPUT fact ("F12"). None →
    /// the generic guidance table is printed instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_menu_key: Option<String>,
    /// WHERE the password/recovery key is kept — a location, in
    /// the user's own words. Never the password itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hint_location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backup: Option<LastBackupFact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rehearsal: Option<LastRehearsalFact>,
    pub generated_unix: u64,
    /// SafeReturn version that generated the card.
    pub app_version: String,
}

fn check_drive(what: &str, d: &DriveIdentification) -> Result<()> {
    if d.model.trim().is_empty() {
        return Err(CoreError::RecoveryCardInvalidFacts {
            reason: format!("the {what} drive has no model — a card that cannot identify the drive is worse than no card"),
        });
    }
    if d.serial_suffix.chars().count() != 4 {
        return Err(CoreError::RecoveryCardInvalidFacts {
            reason: format!(
                "the {what} drive's serial suffix must be exactly the last 4 characters, got '{}'",
                d.serial_suffix
            ),
        });
    }
    Ok(())
}

/// Validate the facts before rendering. A card printed with wrong
/// drive identification sends a stressed reader to the wrong disk,
/// so unusable facts refuse rather than render.
pub fn validate_facts(facts: &RecoveryCardFacts) -> Result<()> {
    if facts.pc_description.trim().is_empty() {
        return Err(CoreError::RecoveryCardInvalidFacts {
            reason: "the PC description is empty — the reader must be able to tell which PC this card is for".to_string(),
        });
    }
    check_drive("backup", &facts.backup_drive)?;
    if let Some(media) = &facts.media {
        check_drive("recovery media", media)?;
    }
    if let Some(key) = &facts.boot_menu_key {
        if key.trim().is_empty() {
            return Err(CoreError::RecoveryCardInvalidFacts {
                reason: "the boot-menu key was stated as empty — leave it unknown so the guidance table prints instead".to_string(),
            });
        }
    }
    Ok(())
}

/// "2023-11-14 22:13 UTC" from unix seconds (civil-from-days;
/// the same algorithm the CLI renders with, duplicated here as a
/// small pure function because core cannot depend on the CLI).
pub fn format_unix_utc(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{year:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        secs / 3600,
        (secs % 3600) / 60
    )
}

fn drive_line(d: &DriveIdentification) -> String {
    let label = d
        .label
        .as_deref()
        .map(|l| format!(" (labelled \"{l}\")"))
        .unwrap_or_default();
    format!("{} — serial ends {}{}", d.model, d.serial_suffix, label)
}

/// Common vendors' boot-menu keys, as GENERIC GUIDANCE. Printed
/// only when this PC's key is unknown, and labelled as guidance.
pub const BOOT_KEY_GUIDANCE: [(&str, &str); 8] = [
    ("Dell", "F12"),
    ("HP", "F9 (or Esc, then F9)"),
    ("Lenovo", "F12 (or the Novo button)"),
    ("ASUS", "F8 (or Esc)"),
    ("Acer", "F12 (may need enabling in setup first)"),
    ("MSI", "F11"),
    ("Gigabyte", "F12"),
    ("Microsoft Surface", "hold Volume Up while pressing Power"),
];

const FILE_STEPS: [&str; 3] = [
    "Start the PC normally and plug in the backup drive (below). Open SafeReturn and choose Restore files.",
    "Pick the backup and the files you want, then choose where they should go.",
    "Wait for SafeReturn to say the files are restored and checked. Open one to be sure.",
];

const WHOLE_PC_STEPS: [&str; 3] = [
    "Plug in the backup drive AND the recovery USB. Restart the PC and open its boot menu (key below), then choose the USB.",
    "In SafeReturn Recovery, pick the backup, choose \"Restore the whole PC\", and pick the PC's own disk as the target. Read the plan — restoring erases that disk completely.",
    "Confirm, wait for the restore and its checks to finish, then remove the USB and restart. If Windows does not start, boot the USB again and ask for help with the support summary below.",
];

// ---------------------------------------------------------------------------
// Plain text

pub fn render_card_text(facts: &RecoveryCardFacts) -> Result<String> {
    validate_facts(facts)?;
    let mut s = String::new();
    s.push_str("SAFERETURN RECOVERY CARD\n");
    s.push_str(&format!("For: {}\n", facts.pc_description));
    s.push_str(&format!(
        "Made: {} · SafeReturn {}\n",
        format_unix_utc(facts.generated_unix),
        facts.app_version
    ));
    s.push_str("\nWHAT TO PLUG IN\n");
    s.push_str(&format!(
        "  Backup drive: {}\n",
        drive_line(&facts.backup_drive)
    ));
    match &facts.media {
        Some(media) => s.push_str(&format!(
            "  Recovery USB to boot from: {}\n",
            drive_line(media)
        )),
        None => s.push_str(
            "  Recovery USB: none recorded. Make one in SafeReturn (Recovery media) before you need it.\n",
        ),
    }
    s.push_str("\nOPENING THE BOOT MENU (for whole-PC restore)\n");
    match &facts.boot_menu_key {
        Some(key) => s.push_str(&format!(
            "  This PC's boot-menu key: {key} — press it repeatedly as the PC starts.\n"
        )),
        None => {
            s.push_str("  This PC's boot-menu key is not recorded. Common keys by maker (general guidance — your PC may differ):\n");
            for (vendor, key) in BOOT_KEY_GUIDANCE {
                s.push_str(&format!("    {vendor}: {key}\n"));
            }
        }
    }
    s.push_str("\nTO GET FILES BACK\n");
    for (i, step) in FILE_STEPS.iter().enumerate() {
        s.push_str(&format!("  {}. {step}\n", i + 1));
    }
    s.push_str("\nTO BRING THE WHOLE PC BACK\n");
    for (i, step) in WHOLE_PC_STEPS.iter().enumerate() {
        s.push_str(&format!("  {}. {step}\n", i + 1));
    }
    s.push_str("\nYOUR BACKUP PASSWORD\n");
    match &facts.password_hint_location {
        Some(loc) => s.push_str(&format!(
            "  Where it is kept (a location, written by you): {loc}\n"
        )),
        None => s.push_str(
            "  Where it is kept: not recorded. Write the LOCATION here by hand — never the password itself: ____________________\n",
        ),
    }
    s.push_str(&format!("  {NO_PASSWORD_LINE}\n"));
    s.push_str("\nLAST BACKUP AND TESTS\n");
    match &facts.last_backup {
        Some(b) => s.push_str(&format!(
            "  Last backup: \"{}\" — {} ({} files, {})\n",
            b.label,
            format_unix_utc(b.created_unix),
            b.file_count,
            crate::engine::format_bytes(b.total_bytes)
        )),
        None => s.push_str("  Last backup: none recorded on this card.\n"),
    }
    match &facts.last_rehearsal {
        Some(r) => s.push_str(&format!(
            "  Last rehearsal: {} — {}: {}\n",
            r.level_label,
            format_unix_utc(r.unix),
            r.summary
        )),
        None => s.push_str(
            "  Last rehearsal: NOT TESTED YET. Test your recovery in SafeReturn before you need it — a backup that has never been test-restored is a hope, not a plan.\n",
        ),
    }
    s.push_str("\nSUPPORT SUMMARY\n");
    match &facts.last_backup {
        Some(b) => s.push_str(&format!("  Backup ID: {}\n", b.set_id)),
        None => s.push_str("  Backup ID: none recorded\n"),
    }
    s.push_str(&format!("  SafeReturn version: {}\n", facts.app_version));
    s.push_str("  If you ask for help, read out this summary and say what the screen shows, word for word.\n");
    Ok(s)
}

// ---------------------------------------------------------------------------
// HTML (standalone, printable, no external resources)

fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn render_card_html(facts: &RecoveryCardFacts) -> Result<String> {
    validate_facts(facts)?;
    let mut s = String::new();
    s.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    s.push_str(&format!(
        "<title>SafeReturn Recovery Card — {}</title>\n",
        esc(&facts.pc_description)
    ));
    s.push_str(
        "<style>body{font-family:'Segoe UI',Arial,sans-serif;max-width:44em;margin:2em auto;padding:0 1em;color:#111}\
         h1{font-size:1.9em;margin-bottom:0}h2{font-size:1.3em;margin-top:1.4em;border-bottom:2px solid #b00020;padding-bottom:.15em}\
         .big{font-size:1.15em}li{margin:.35em 0}.key{font-weight:700;border:2px solid #111;border-radius:.3em;padding:.05em .4em}\
         .warn{background:#fff4e5;border:1px solid #b00020;padding:.6em .8em}.small{color:#333;font-size:.92em}\
         @media print{body{margin:0}}</style>\n</head>\n<body>\n",
    );
    s.push_str("<h1>SafeReturn Recovery Card</h1>\n");
    s.push_str(&format!(
        "<p class=\"big\">For: <strong>{}</strong></p>\n",
        esc(&facts.pc_description)
    ));
    s.push_str(&format!(
        "<p class=\"small\">Made: {} · SafeReturn {}</p>\n",
        esc(&format_unix_utc(facts.generated_unix)),
        esc(&facts.app_version)
    ));

    s.push_str("<h2>What to plug in</h2>\n<ul>\n");
    s.push_str(&format!(
        "<li>Backup drive: <strong>{}</strong></li>\n",
        esc(&drive_line(&facts.backup_drive))
    ));
    match &facts.media {
        Some(media) => s.push_str(&format!(
            "<li>Recovery USB to boot from: <strong>{}</strong></li>\n",
            esc(&drive_line(media))
        )),
        None => s.push_str(
            "<li>Recovery USB: none recorded. Make one in SafeReturn (Recovery media) before you need it.</li>\n",
        ),
    }
    s.push_str("</ul>\n");

    s.push_str("<h2>Opening the boot menu (for whole-PC restore)</h2>\n");
    match &facts.boot_menu_key {
        Some(key) => s.push_str(&format!(
            "<p class=\"big\">This PC's boot-menu key: <span class=\"key\">{}</span> — press it repeatedly as the PC starts.</p>\n",
            esc(key)
        )),
        None => {
            s.push_str("<p>This PC's boot-menu key is not recorded. Common keys by maker — <em>general guidance; your PC may differ</em>:</p>\n<table>\n");
            for (vendor, key) in BOOT_KEY_GUIDANCE {
                s.push_str(&format!(
                    "<tr><td>{}</td><td><span class=\"key\">{}</span></td></tr>\n",
                    esc(vendor),
                    esc(key)
                ));
            }
            s.push_str("</table>\n");
        }
    }

    s.push_str("<h2>To get files back</h2>\n<ol>\n");
    for step in FILE_STEPS {
        s.push_str(&format!("<li class=\"big\">{}</li>\n", esc(step)));
    }
    s.push_str("</ol>\n<h2>To bring the whole PC back</h2>\n<ol>\n");
    for step in WHOLE_PC_STEPS {
        s.push_str(&format!("<li class=\"big\">{}</li>\n", esc(step)));
    }
    s.push_str("</ol>\n");

    s.push_str("<h2>Your backup password</h2>\n");
    match &facts.password_hint_location {
        Some(loc) => s.push_str(&format!(
            "<p class=\"big\">Where it is kept (a location, written by you): <strong>{}</strong></p>\n",
            esc(loc)
        )),
        None => s.push_str(
            "<p class=\"big\">Where it is kept: not recorded. Write the LOCATION here by hand — never the password itself: ____________________</p>\n",
        ),
    }
    s.push_str(&format!("<p class=\"warn\">{NO_PASSWORD_LINE}</p>\n"));

    s.push_str("<h2>Last backup and tests</h2>\n<ul>\n");
    match &facts.last_backup {
        Some(b) => s.push_str(&format!(
            "<li>Last backup: \"{}\" — {} ({} files, {})</li>\n",
            esc(&b.label),
            esc(&format_unix_utc(b.created_unix)),
            b.file_count,
            crate::engine::format_bytes(b.total_bytes)
        )),
        None => s.push_str("<li>Last backup: none recorded on this card.</li>\n"),
    }
    match &facts.last_rehearsal {
        Some(r) => s.push_str(&format!(
            "<li>Last rehearsal: {} — {}: {}</li>\n",
            esc(&r.level_label),
            esc(&format_unix_utc(r.unix)),
            esc(&r.summary)
        )),
        None => s.push_str(
            "<li>Last rehearsal: <strong>NOT TESTED YET.</strong> Test your recovery in SafeReturn before you need it — a backup that has never been test-restored is a hope, not a plan.</li>\n",
        ),
    }
    s.push_str("</ul>\n<h2>Support summary</h2>\n<ul>\n");
    match &facts.last_backup {
        Some(b) => s.push_str(&format!("<li>Backup ID: {}</li>\n", esc(&b.set_id))),
        None => s.push_str("<li>Backup ID: none recorded</li>\n"),
    }
    s.push_str(&format!(
        "<li>SafeReturn version: {}</li>\n",
        esc(&facts.app_version)
    ));
    s.push_str("<li>If you ask for help, read out this summary and say what the screen shows, word for word.</li>\n</ul>\n</body>\n</html>\n");
    Ok(s)
}
