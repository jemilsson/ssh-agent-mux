//! Peer attribution for accepted connections.
//!
//! Captures `SO_PEERCRED` from the connecting Unix socket and walks `/proc`
//! to record the client's command line plus a chain of ancestor PIDs. The
//! chain lets log lines name the originating tool (e.g. `claude → node → git
//! → ssh`) instead of only the direct caller (`ssh`).

use std::fmt;
use std::fs;

use tokio::net::UnixStream;

/// Maximum ancestors walked via `PPid` in `/proc/<pid>/status`.
const MAX_ANCESTRY_DEPTH: usize = 5;
/// Per-cmdline truncation in the `Display` output.
const CMDLINE_DISPLAY_MAX: usize = 80;

pub struct PeerInfo {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    pub cmdline: String,
    /// (pid, cmdline) walking up from the client, excluding the client itself.
    pub ancestry: Vec<(i32, String)>,
}

impl PeerInfo {
    /// One-line summary for use in a notification body. Surfaces the
    /// immediate caller's argv (typically `ssh user@host` or similar)
    /// on its own line, followed by the parent chain rendered as
    /// program basenames so the user sees what triggered the signing.
    pub fn notification_body(&self) -> String {
        let caller = truncate(&self.cmdline, CMDLINE_DISPLAY_MAX * 2);
        if self.ancestry.is_empty() {
            return format!("from: {}", caller);
        }
        let chain: Vec<&str> = self
            .ancestry
            .iter()
            .map(|(_, cmd)| basename(cmd))
            .collect();
        format!("from: {}\nvia:  {}", caller, chain.join(" \u{2190} "))
    }

    pub fn capture(stream: &UnixStream) -> Option<Self> {
        let cred = stream.peer_cred().ok()?;
        let pid = cred.pid()?;
        let cmdline = read_cmdline(pid).unwrap_or_else(|| "<unreadable>".to_string());

        let mut ancestry = Vec::with_capacity(MAX_ANCESTRY_DEPTH);
        let mut cursor = read_ppid(pid);
        while let Some(ppid) = cursor {
            if ppid <= 1 || ancestry.len() >= MAX_ANCESTRY_DEPTH {
                break;
            }
            let anc_cmd = read_cmdline(ppid).unwrap_or_else(|| "<unreadable>".to_string());
            ancestry.push((ppid, anc_cmd));
            cursor = read_ppid(ppid);
        }

        Some(PeerInfo {
            pid,
            uid: cred.uid(),
            gid: cred.gid(),
            cmdline,
            ancestry,
        })
    }
}

fn read_cmdline(pid: i32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        // Kernel threads or zombies have empty cmdline; fall back to comm.
        return fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string());
    }
    // cmdline is NUL-separated argv; convert to space-separated.
    let parts: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    Some(parts.join(" "))
}

fn read_ppid(pid: i32) -> Option<i32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Basename of the first argv token. Strips `/nix/store/<hash>-<name>/...`
/// down to just `<name>`-like segments so notification chains stay readable.
fn basename(cmdline: &str) -> &str {
    let first = cmdline.split_whitespace().next().unwrap_or(cmdline);
    first.rsplit('/').next().unwrap_or(first)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max.saturating_sub(1);
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

impl fmt::Display for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pid={}({}) uid={}",
            self.pid,
            truncate(&self.cmdline, CMDLINE_DISPLAY_MAX),
            self.uid
        )?;
        for (apid, acmd) in &self.ancestry {
            write!(f, " ← {}({})", apid, truncate(acmd, CMDLINE_DISPLAY_MAX))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_ascii() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5), "hell…");
    }

    #[test]
    fn read_cmdline_self() {
        let cmdline = read_cmdline(std::process::id() as i32);
        assert!(cmdline.is_some());
    }

    #[test]
    fn read_ppid_self() {
        let ppid = read_ppid(std::process::id() as i32);
        assert!(ppid.is_some());
        assert!(ppid.unwrap() > 0);
    }

    #[test]
    fn basename_strips_nix_store_path() {
        assert_eq!(basename("/nix/store/abc-zsh-5.9/bin/zsh -c foo"), "zsh");
        assert_eq!(basename("ssh git@github.com"), "ssh");
        assert_eq!(basename("/usr/bin/git push"), "git");
        assert_eq!(basename(""), "");
    }

    #[test]
    fn notification_body_includes_caller_and_chain() {
        let p = PeerInfo {
            pid: 1234,
            uid: 1000,
            gid: 1000,
            cmdline: "ssh git@github.com".to_string(),
            ancestry: vec![
                (1230, "/nix/store/x-zsh-5.9/bin/zsh".to_string()),
                (1200, "/nix/store/y-kitty-0.4/bin/kitty".to_string()),
            ],
        };
        let body = p.notification_body();
        assert!(body.contains("from: ssh git@github.com"));
        assert!(body.contains("via:  zsh \u{2190} kitty"));
    }
}
