//! Best-effort desktop notifications via libnotify (`notify-send`).
//!
//! Each sign request fires a persistent notification with the connecting
//! peer chain (e.g. `claude → node → git → ssh git@github.com`) and a
//! 7-char id derived from `SHA-256(sign_data)`, encoded in standard
//! base64 without padding to match the OpenSSH `SHA256:<base64>`
//! fingerprint convention. linux-id computes the same id from the
//! matching CTAP2 `clientDataHash` and includes it in its pinentry
//! prompt, so the user can confirm both notifications belong to the same
//! request.
//!
//! `send` returns a [`Handle`] whose [`Drop`] impl closes the
//! notification via the `org.freedesktop.Notifications.CloseNotification`
//! D-Bus method (invoked through `dbus-send`). The notification is fired
//! with `--urgency=critical --expire-time=0` so it persists until the
//! sign returns (success, denial, or timeout) and the handle is dropped.
//!
//! Everything is best-effort. A missing `notify-send` or `dbus-send`,
//! no D-Bus session, or any spawn failure is silently ignored. A sign
//! must never fail because the desktop is unreachable.

use std::process::{Command, Stdio};
use std::sync::OnceLock;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

const ID_LEN: usize = 7;

static NOTIFY_BIN: OnceLock<Option<String>> = OnceLock::new();

fn locate(name: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|p| p.join(name))
            .find(|p| p.is_file())
            .map(|p| p.to_string_lossy().into_owned())
    })
}

fn notify_bin() -> Option<&'static str> {
    NOTIFY_BIN
        .get_or_init(|| locate("notify-send"))
        .as_deref()
}

/// Full base64 (no padding) of `SHA-256(data)`. 43 chars for SHA-256.
pub fn hash(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    STANDARD_NO_PAD.encode(digest)
}

/// 7-char prefix of `hash(data)`, suitable for in-the-moment visual
/// correlation with linux-id's pinentry prompt.
pub fn short_id(data: &[u8]) -> String {
    let mut s = hash(data);
    s.truncate(ID_LEN);
    s
}

/// A live persistent notification. Drops close it via D-Bus.
pub struct Handle {
    id: u32,
}

impl Drop for Handle {
    fn drop(&mut self) {
        let Some(bin) = locate("dbus-send") else {
            return;
        };
        let _ = Command::new(bin)
            .args([
                "--session",
                "--type=method_call",
                "--dest=org.freedesktop.Notifications",
                "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications.CloseNotification",
                &format!("uint32:{}", self.id),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}

/// Fire a persistent notification and return a handle that closes it on
/// drop. Returns `None` if `notify-send` is unavailable or the call fails.
pub fn send(title: &str, body: &str) -> Option<Handle> {
    let bin = notify_bin()?;
    let output = Command::new(bin)
        .args([
            "--app-name=ssh-agent-mux",
            "--category=device",
            "--urgency=critical",
            "--expire-time=0",
            "--print-id",
            title,
            body,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let id: u32 = String::from_utf8_lossy(&output.stdout).trim().parse().ok()?;
    Some(Handle { id })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_43_base64_chars_for_sha256() {
        let h = hash(b"hello");
        assert_eq!(h.len(), 43);
        // No padding, standard alphabet (A-Z a-z 0-9 + /).
        assert!(h
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
    }

    #[test]
    fn short_id_is_prefix_of_hash() {
        let data = b"correlate me";
        let id = short_id(data);
        let h = hash(data);
        assert_eq!(id.len(), ID_LEN);
        assert!(h.starts_with(&id), "short id must be a prefix of full hash");
    }

    #[test]
    fn short_id_is_deterministic() {
        assert_eq!(short_id(b"abc"), short_id(b"abc"));
        assert_ne!(short_id(b"abc"), short_id(b"abd"));
    }
}
