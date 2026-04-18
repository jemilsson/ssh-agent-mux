//! Best-effort desktop notifications via libnotify (`notify-send`).
//!
//! Each sign request fires a notification with the connecting peer chain
//! (e.g. `claude → node → git → ssh git@github.com`) and a 7-hex-char id
//! derived from `SHA-256(sign_data)`. linux-id computes the same id from
//! the matching CTAP2 `clientDataHash` and includes it in its pinentry
//! prompt, so the user can confirm both notifications belong to the same
//! request.
//!
//! All sends are fire-and-forget. A missing `notify-send`, no D-Bus
//! session, or any spawn failure is silently ignored. A sign must never
//! fail because the desktop is unreachable.

use std::process::{Command, Stdio};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

const ID_LEN: usize = 7;

static NOTIFY_BIN: OnceLock<Option<String>> = OnceLock::new();

fn locate() -> Option<&'static str> {
    NOTIFY_BIN
        .get_or_init(|| {
            // PATH lookup; ignore failures.
            std::env::var_os("PATH").and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|p| p.join("notify-send"))
                    .find(|p| p.is_file())
                    .map(|p| p.to_string_lossy().into_owned())
            })
        })
        .as_deref()
}

/// 7-hex-char id from arbitrary bytes (matching git's short-hash convention).
pub fn short_id(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(ID_LEN);
    for byte in digest.iter() {
        if s.len() >= ID_LEN {
            break;
        }
        s.push_str(&format!("{:02x}", byte));
    }
    s.truncate(ID_LEN);
    s
}

/// Fire a notification asynchronously. Never blocks the caller.
pub fn send(title: &str, body: &str) {
    let Some(bin) = locate() else {
        return;
    };
    let _ = Command::new(bin)
        .args([
            "--app-name=ssh-agent-mux",
            "--category=device",
            "--urgency=normal",
            "--expire-time=15000",
            title,
            body,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    // Spawned process is reaped by the kernel after exit; we don't wait.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_is_seven_hex_chars() {
        let id = short_id(b"hello");
        assert_eq!(id.len(), ID_LEN);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn short_id_is_deterministic() {
        assert_eq!(short_id(b"abc"), short_id(b"abc"));
        assert_ne!(short_id(b"abc"), short_id(b"abd"));
    }
}
