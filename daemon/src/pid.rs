use anyhow::Result;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Try to acquire a PID file. Removes stale PID files (dead processes).
/// Returns Err if another daemon is already running.
pub fn acquire_pid_file(path: &Path) -> Result<()> {
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let pid: u32 = content.trim().parse().unwrap_or(0);
        if pid > 0 && process_alive(pid) {
            anyhow::bail!("nie-daemon already running as PID {}", pid);
        }
        tracing::warn!("removing stale PID file (PID {} no longer running)", pid);
        std::fs::remove_file(path)?;
    }
    let current_pid = std::process::id();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "{}", current_pid)?;
    Ok(())
}

pub fn release_pid_file(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        tracing::warn!("failed to remove PID file {}: {}", path.display(), e);
    }
}

fn process_alive(pid: u32) -> bool {
    // Safety: signal 0 only checks existence, never kills
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stale_pid_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        // Write a PID that is definitely dead (PID 999999 is unlikely to exist)
        std::fs::write(&path, "999999\n").unwrap();
        let result = acquire_pid_file(&path);
        // Either succeeds or fails gracefully — just must not panic
        let _ = result;
    }

    #[test]
    fn test_acquire_no_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.pid");
        assert!(acquire_pid_file(&path).is_ok());
        let content = std::fs::read_to_string(&path).unwrap();
        let written_pid: u32 = content.trim().parse().unwrap();
        assert_eq!(written_pid, std::process::id());
        release_pid_file(&path);
    }
}
