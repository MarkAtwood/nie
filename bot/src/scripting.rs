use std::time::Duration;

use anyhow::Result;
use tokio::process::Command;
use tokio::time::timeout;

use crate::BotError;

/// Hard timeout for hook execution.
const HOOK_TIMEOUT_SECS: u64 = 30;
/// Maximum bytes captured from hook stdout. Longer output is silently truncated.
const HOOK_STDOUT_MAX_BYTES: usize = 65_536;
/// Maximum bytes captured from hook stderr. Longer output is silently truncated.
const HOOK_STDERR_MAX_BYTES: usize = 8_192;

/// Result of running a hook script.
#[derive(Debug)]
pub struct HookResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Execute a user-configured hook command safely.
///
/// Uses shlex::split + Command::new — NOT sh -c — to prevent shell injection.
/// The hook receives message context via environment variables (NIE_FROM, NIE_TEXT, NIE_TS).
/// stdin is always /dev/null (hook cannot read bot's stdin).
/// stdout is capped at `HOOK_STDOUT_MAX_BYTES`; stderr at `HOOK_STDERR_MAX_BYTES`.
/// Timeout: `HOOK_TIMEOUT_SECS` seconds (hard limit).
pub async fn run_hook(cmd_str: &str, env_vars: &[(&str, &str)]) -> Result<HookResult> {
    // Step 1: shlex-split the command string — NOT sh -c (shell injection boundary)
    let argv = shlex::split(cmd_str)
        .ok_or_else(|| BotError::Config(format!("hook command has unmatched quotes: {cmd_str}")))?;

    if argv.is_empty() {
        return Err(BotError::Config("hook command is empty".to_string()).into());
    }

    // Step 2: Spawn with explicit stdio — NOT sh -c
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| BotError::Config(format!("failed to spawn hook {:?}: {e}", &argv[0])))?;

    // Step 3: Wait with hard timeout.
    // We use wait() (&mut self) rather than wait_with_output() (self) so that
    // child remains accessible for kill() if the timeout fires.
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let wait_result = timeout(
        Duration::from_secs(HOOK_TIMEOUT_SECS),
        child.wait(),
    )
    .await;

    let status = match wait_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_elapsed) => {
            let _ = child.kill().await;
            return Err(BotError::ScriptTimeout {
                path: argv[0].clone(),
                secs: HOOK_TIMEOUT_SECS,
            }
            .into());
        }
    };

    // Collect stdout and stderr from the pipe handles now that the process has exited.
    use tokio::io::AsyncReadExt;
    let mut raw_stdout = Vec::new();
    if let Some(mut h) = stdout_handle {
        let _ = h.read_to_end(&mut raw_stdout).await;
    }
    let mut raw_stderr = Vec::new();
    if let Some(mut h) = stderr_handle {
        let _ = h.read_to_end(&mut raw_stderr).await;
    }

    // Step 4: Cap stdout and stderr
    let stdout = String::from_utf8_lossy(&raw_stdout[..raw_stdout.len().min(HOOK_STDOUT_MAX_BYTES)]).into_owned();
    let stderr = String::from_utf8_lossy(&raw_stderr[..raw_stderr.len().min(HOOK_STDERR_MAX_BYTES)]).into_owned();
    let exit_code = status.code().unwrap_or(-1);

    Ok(HookResult {
        exit_code,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: `echo` is a POSIX utility that prints its argument followed by a newline.
    /// Expected output "hello\n" is known independently of scripting.rs code.
    #[tokio::test]
    async fn test_hook_echo() {
        let result = run_hook("echo hello", &[]).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(
            result.stdout.contains("hello"),
            "stdout was: {:?}",
            result.stdout
        );
    }

    /// Oracle: shlex rejects unterminated single quotes and returns None,
    /// which run_hook maps to BotError::Config.
    #[tokio::test]
    async fn test_hook_unmatched_quote() {
        let err = run_hook("echo 'bad", &[]).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unmatched quotes") || msg.contains("Config"),
            "error message was: {:?}",
            msg
        );
    }

    /// SECURITY TEST: shell injection prevention.
    ///
    /// If sh -c were used, "echo foo;cat /etc/passwd" would run two commands and
    /// output /etc/passwd content. With shlex + Command::new, the semicolon is a
    /// literal character — it is passed as a single argument to echo.
    /// Oracle: POSIX `echo` prints its arguments verbatim; "foo;cat" is the argument.
    #[tokio::test]
    async fn test_hook_no_shell_injection() {
        let result = run_hook("echo foo;cat /etc/passwd", &[]).await.unwrap();
        assert_eq!(result.exit_code, 0);
        // The literal string "foo;cat" must appear — echo received it as one argument
        assert!(
            result.stdout.contains("foo;cat"),
            "stdout was: {:?}",
            result.stdout
        );
        // /etc/passwd content must NOT appear — if it does, sh -c was used
        assert!(
            !result.stdout.contains("root:"),
            "SECURITY FAILURE: /etc/passwd content in stdout: {:?}",
            result.stdout
        );
    }

    /// Oracle: `env` prints all environment variables to stdout, one per line,
    /// in KEY=VALUE format. We inject NIE_FROM so it must appear.
    #[tokio::test]
    async fn test_hook_env_var_passed() {
        let result = run_hook("env", &[("NIE_FROM", "testpub123")])
            .await
            .unwrap();
        assert!(
            result.stdout.contains("NIE_FROM=testpub123"),
            "stdout was: {:?}",
            result.stdout
        );
    }

    /// Oracle: an empty command string has no argv[0]; run_hook must reject it
    /// before attempting to spawn anything (BotError::Config).
    #[tokio::test]
    async fn test_hook_empty_command() {
        let err = run_hook("", &[]).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("empty") || msg.contains("Config"),
            "error message was: {:?}",
            msg
        );
    }
}
