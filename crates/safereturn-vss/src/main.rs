//! S0 spike binary.
//! On Windows: runs the safe VSS probe (no snapshot is created).
//! Elsewhere: prints the documented sequence the state machine enforces.

fn main() {
    #[cfg(windows)]
    {
        match safereturn_vss::win::probe() {
            Ok(steps) => {
                println!("VSS probe OK (elevated requester, no snapshot created):");
                for s in steps {
                    println!("  {s}");
                }
            }
            Err(e) => {
                eprintln!("VSS probe failed: {e}");
                eprintln!("Reminder: the probe must run elevated (admin + backup privilege).");
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(windows))]
    {
        let mut s = safereturn_vss::VssSession::new();
        s.initialize_for_backup().unwrap();
        s.set_backup_state().unwrap();
        s.gather_writer_metadata().unwrap();
        s.start_snapshot_set().unwrap();
        s.add_to_snapshot_set("C:\\").unwrap();
        s.prepare_for_backup().unwrap();
        s.do_snapshot_set().unwrap();
        s.backup_complete().unwrap();
        s.release().unwrap();
        println!("Documented VSS sequence (state-machine dry run):");
        for step in &s.call_log {
            println!("  {step}");
        }
    }
}
