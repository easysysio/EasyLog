// =============================================================================
// logtype/linux.rs — Linux system logs: every line kept, security events parsed
//
// A Linux server forwards everything it logs (`*.* @easylog` in rsyslog), and a
// source maps to exactly one log type — so this type cannot be choosy the way a
// web-server parser is. Every line is stored, with the program and PID taken
// from the syslog tag. On top of that, the lines that matter for security are
// read into structured columns:
//
//   sshd        Accepted …                     → login_ok
//               Failed <method> for …          → login_failed
//               Invalid user …                 → invalid_user
//               … [preauth] disconnects/limits → preauth
//   sudo        user : TTY=… ; USER=… ; COMMAND=…   → sudo
//               user : <reason> ; …             → sudo_failed
//   su          (to root) user / Successful su  → su
//               FAILED SU / FAILED su           → su_failed
//   pam_unix    authentication failure (other services: console login,
//               display managers, ftp, mail …)  → login_failed
//   useradd, userdel, usermod, passwd, groupadd, … → account
//
// pam_unix also logs a failure for sshd, sudo and su — but those programs log
// the same attempt themselves, so the PAM line is left as plain text rather
// than counted twice.
//
// The client address of a remote login is geolocated, which is what puts SSH
// brute-forcing on the world map. Lines with no client carry no country.
//
// The time is the arrival time: a classic syslog timestamp has no year and no
// zone, and the sender's clock is not ours to trust.
// =============================================================================

use std::net::IpAddr;
use std::sync::OnceLock;

use anyhow::Result;
use duckdb::{Connection, params};
use regex::Regex;

use super::{Category, LogType, Meta};

/// Linux system-log handler (zero-sized).
pub struct Linux;

/// Every security event the parser recognises, as stored in `event`, in the
/// order the dashboard lists them. Lines that are none of these keep "".
pub const EVENTS: [&str; 9] = [
    "login_failed",
    "invalid_user",
    "preauth",
    "login_ok",
    "sudo",
    "sudo_failed",
    "su",
    "su_failed",
    "account",
];

/// Programs whose every line is an account or group change.
const ACCOUNT_PROGRAMS: [&str; 11] = [
    "useradd", "userdel", "usermod", "adduser", "deluser", "groupadd", "groupdel", "groupmod",
    "passwd", "chpasswd", "gpasswd",
];

/// One received line, split into its header and, where recognised, an event.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LinuxLine {
    pub program: String,
    pub pid: Option<i32>,
    /// The message after the `program[pid]:` prefix.
    pub message: String,
    /// One of EVENTS, or "" for an ordinary line.
    pub event: &'static str,
    /// "success", "failure", or "" for events that are neither.
    pub outcome: &'static str,
    /// Who acted: the login name, the sudo/su caller.
    pub user: String,
    /// Who they became (sudo/su), or the account changed.
    pub target_user: String,
    /// Remote address of a login attempt.
    pub client: String,
    pub port: Option<i32>,
    /// Authentication method (password, publickey), PAM service, or the reason a
    /// sudo was refused.
    pub method: String,
    /// The sudo command, or what an account change did.
    pub command: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// re(cell, pattern)
// Compiles a pattern once into its static cell and hands back the regex.
// ─────────────────────────────────────────────────────────────────────────────
fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("linux log regex is valid"))
}

// ─────────────────────────────────────────────────────────────────────────────
// split_header(raw, meta)
// Finds the program, PID and message. RFC 3164 puts `program[pid]: message`
// after the hostname; RFC 5424 puts `program pid msgid sd message`, and the
// syslog parser has already cut the message out (`raw`). meta.body is read
// rather than raw because the parser may have taken a tagless line's first
// word for the program.
// ─────────────────────────────────────────────────────────────────────────────
fn split_header(raw: &str, meta: &Meta) -> (String, Option<i32>, String) {
    static TAGGED: OnceLock<Regex> = OnceLock::new();
    let body = if meta.body.trim().is_empty() { raw } else { meta.body.as_str() };
    let body = body.trim();

    if let Some(c) = re(&TAGGED, r"^([^\s\[:]+)(?:\[(\d+)\])?:\s*(.*)$").captures(body) {
        return (
            c[1].to_string(),
            c.get(2).and_then(|p| p.as_str().parse().ok()),
            c[3].trim().to_string(),
        );
    }
    // RFC 5424: the body starts "program procid …" and raw is the message.
    if let Some(tag) = meta.tag.as_deref().filter(|t| !t.is_empty())
        && let Some(rest) = body.strip_prefix(tag).filter(|r| r.starts_with(' '))
    {
        let pid = rest.split_whitespace().next().and_then(|p| p.parse().ok());
        return (tag.to_string(), pid, raw.trim().to_string());
    }
    (meta.tag.clone().unwrap_or_default(), None, body.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_line(raw, meta)
// Splits the header and recognises the event, if any. Never fails: a line that
// is not a security event is still a line to keep.
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_line(raw: &str, meta: &Meta) -> LinuxLine {
    let (program, pid, message) = split_header(raw, meta);
    let mut line = LinuxLine {
        program,
        pid,
        message,
        ..Default::default()
    };
    let prog = line.program.to_ascii_lowercase();
    let msg = line.message.clone();

    // OpenSSH 9.8+ logs the per-connection work as sshd-session (and sshd-auth).
    if prog.starts_with("sshd") {
        sshd(&msg, &mut line);
    } else if prog == "sudo" {
        sudo(&msg, &mut line);
    } else if prog == "su" || prog.starts_with("su-") {
        su(&msg, &mut line);
    } else if ACCOUNT_PROGRAMS.contains(&prog.as_str()) {
        account(&msg, &mut line);
    }
    if line.event.is_empty() {
        pam_failure(&msg, &mut line);
    }
    line.outcome = match line.event {
        "login_ok" | "sudo" | "su" => "success",
        "login_failed" | "invalid_user" | "preauth" | "sudo_failed" | "su_failed" => "failure",
        _ => "",
    };
    line
}

// ─────────────────────────────────────────────────────────────────────────────
// sshd(msg, line)
// OpenSSH's authentication lines. The order matters: "Failed … for invalid user"
// must be read as a failed login, not as the separate "Invalid user" notice.
// ─────────────────────────────────────────────────────────────────────────────
fn sshd(msg: &str, line: &mut LinuxLine) {
    static ACCEPTED: OnceLock<Regex> = OnceLock::new();
    static FAILED: OnceLock<Regex> = OnceLock::new();
    static INVALID: OnceLock<Regex> = OnceLock::new();
    static ADDR_PORT: OnceLock<Regex> = OnceLock::new();
    static PRE_USER: OnceLock<Regex> = OnceLock::new();

    let accepted = re(&ACCEPTED, r"^Accepted (\S+) for (.*?) from (\S+) port (\d+)");
    let failed = re(&FAILED, r"^Failed (\S+) for (?:invalid user )?(.*?) from (\S+) port (\d+)");
    let invalid = re(&INVALID, r"^Invalid user (.*?) from (\S+)(?: port (\d+))?");

    if let Some(c) = accepted.captures(msg) {
        line.event = "login_ok";
        line.method = c[1].to_string();
        line.user = c[2].to_string();
        line.client = c[3].to_string();
        line.port = c[4].parse().ok();
    } else if let Some(c) = failed.captures(msg) {
        line.event = "login_failed";
        line.method = c[1].to_string();
        line.user = c[2].to_string();
        line.client = c[3].to_string();
        line.port = c[4].parse().ok();
    } else if let Some(c) = invalid.captures(msg) {
        line.event = "invalid_user";
        line.user = c[1].to_string();
        line.client = c[2].to_string();
        line.port = c.get(3).and_then(|p| p.as_str().parse().ok());
    } else if msg.contains("[preauth]") || msg.starts_with("Timeout before authentication") {
        // A connection that never got past authentication: closed, reset,
        // timed out, or cut off at the attempt limit. Only worth recording
        // when it names the address it came from.
        let addr = re(&ADDR_PORT, r"(\S+) port (\d+)")
            .captures_iter(msg)
            .find(|c| c[1].parse::<IpAddr>().is_ok());
        let Some(addr) = addr else { return };
        line.event = "preauth";
        line.client = addr[1].to_string();
        line.port = addr[2].parse().ok();
        if let Some(u) = re(
            &PRE_USER,
            r"(?:(?:authenticating|invalid) user (\S*) |exceeded for (?:invalid user )?(\S+) from )",
        )
        .captures(msg)
        {
            line.user = u.get(1).or(u.get(2)).map(|m| m.as_str().to_string()).unwrap_or_default();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// sudo(msg, line)
// "caller : [reason ;] TTY=… ; PWD=… ; USER=target ; COMMAND=…". A part with
// no '=' is the reason sudo refused ("3 incorrect password attempts", "user
// NOT in sudoers"); without one, the command ran. COMMAND is read to the end of
// the line, since a command may itself contain " ; ".
// ─────────────────────────────────────────────────────────────────────────────
fn sudo(msg: &str, line: &mut LinuxLine) {
    let Some((caller, rest)) = msg.split_once(" : ") else { return };
    let (fields, command) = match rest.split_once("COMMAND=") {
        Some((f, c)) => (f, c.trim()),
        None => (rest, ""),
    };
    let mut reason = String::new();
    let mut target = String::new();
    for part in fields.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('=') {
            Some(("USER", v)) => target = v.trim().to_string(),
            Some(_) => {}
            None => reason = part.to_string(),
        }
    }
    if reason.is_empty() && command.is_empty() {
        return;
    }
    line.event = if reason.is_empty() { "sudo" } else { "sudo_failed" };
    line.user = caller.trim().to_string();
    line.target_user = target;
    line.method = reason;
    line.command = command.to_string();
}

// ─────────────────────────────────────────────────────────────────────────────
// su(msg, line)
// Both wordings: util-linux ("(to root) bob on pts/0", "FAILED SU (to root)
// bob on pts/0") and shadow ("Successful su for root by bob", "FAILED su for
// root by bob"). The shadow "+ pts/0 bob:root" summary repeats the same switch
// and is left as text.
// ─────────────────────────────────────────────────────────────────────────────
fn su(msg: &str, line: &mut LinuxLine) {
    static UTIL: OnceLock<Regex> = OnceLock::new();
    static SHADOW: OnceLock<Regex> = OnceLock::new();
    let util = re(&UTIL, r"^(FAILED SU )?\(to (\S+)\) (\S+)");
    let shadow = re(&SHADOW, r"^(Successful|FAILED) su for (\S+) by (\S+)");

    let (failed, target, caller) = if let Some(c) = util.captures(msg) {
        (c.get(1).is_some(), c[2].to_string(), c[3].to_string())
    } else if let Some(c) = shadow.captures(msg) {
        (&c[1] == "FAILED", c[2].to_string(), c[3].to_string())
    } else {
        return;
    };
    line.event = if failed { "su_failed" } else { "su" };
    line.user = caller;
    line.target_user = target;
}

// ─────────────────────────────────────────────────────────────────────────────
// account(msg, line)
// Account and group changes. The message itself is what changed; the account
// name is picked out when the program states it.
// ─────────────────────────────────────────────────────────────────────────────
fn account(msg: &str, line: &mut LinuxLine) {
    static NAME: OnceLock<Regex> = OnceLock::new();
    // Session open/close lines from passwd's PAM stack are not changes.
    if msg.contains(":session)") {
        return;
    }
    line.event = "account";
    line.method = line.program.clone();
    line.command = msg.to_string();
    let name = re(
        &NAME,
        r"(?:name=([^,\s]+)|password changed for (\S+)|(?:user|account) '([^']+)'|^\S+ '([^']+)')",
    );
    if let Some(c) = name.captures(msg) {
        line.target_user = (1..=4)
            .find_map(|i| c.get(i))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// pam_failure(msg, line)
// "pam_unix(service:auth): authentication failure; … rhost=… user=…" for a
// service that does not log the attempt itself — console login, a display
// manager, an FTP or mail daemon.
// ─────────────────────────────────────────────────────────────────────────────
fn pam_failure(msg: &str, line: &mut LinuxLine) {
    static PAM: OnceLock<Regex> = OnceLock::new();
    static KV: OnceLock<Regex> = OnceLock::new();
    let Some(c) = re(&PAM, r"pam_unix\(([^:)]+):auth\): authentication failure;(.*)").captures(msg)
    else {
        return;
    };
    let service = c[1].to_string();
    if service.starts_with("sshd") || service.starts_with("sudo") || service.starts_with("su") {
        return;
    }
    line.event = "login_failed";
    line.method = service;
    for kv in re(&KV, r"(\w+)=(\S*)").captures_iter(&c[2]) {
        match &kv[1] {
            "user" => line.user = kv[2].to_string(),
            "rhost" => line.client = kv[2].to_string(),
            _ => {}
        }
    }
}

impl LogType for Linux {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn category(&self) -> Category {
        Category::System
    }

    fn label(&self) -> &'static str {
        "Linux"
    }

    fn icon(&self) -> &'static str {
        "bi-terminal"
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Linux::init_schema(conn)
    // Creates the `linux` table if absent. Every line gets a row; the event
    // columns stay empty for lines that are not security events.
    // ─────────────────────────────────────────────────────────────────────────
    fn init_schema(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS linux (
                source_ip    VARCHAR,
                ts           TIMESTAMP,
                hostname     VARCHAR,
                program      VARCHAR,
                pid          INTEGER,
                event        VARCHAR,
                outcome      VARCHAR,
                "user"       VARCHAR,
                target_user  VARCHAR,
                client       VARCHAR,
                port         INTEGER,
                method       VARCHAR,
                command      VARCHAR,
                country      VARCHAR,
                country_code VARCHAR,
                received_at  TIMESTAMP,
                raw          VARCHAR
            );
            "#,
        )?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Linux::ingest(raw, meta, conn)
    // Stores the line, with its event when it has one. Only an empty message is
    // refused. The client of a login attempt is geolocated; a line with no
    // client has no country (NULL), so it never counts toward one.
    // ─────────────────────────────────────────────────────────────────────────
    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool> {
        let body = if meta.body.trim().is_empty() { raw } else { meta.body.as_str() };
        if body.trim().is_empty() {
            return Ok(false);
        }
        let l = parse_line(raw, meta);
        let (country_code, country) = if l.client.is_empty() {
            (None, None)
        } else {
            let (code, name) = crate::geo::lookup(&l.client);
            (Some(code), Some(name))
        };
        let received = meta.received_at.naive_utc();
        conn.execute(
            r#"INSERT INTO linux
               (source_ip, ts, hostname, program, pid, event, outcome, "user", target_user,
                client, port, method, command, country, country_code, received_at, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#,
            params![
                meta.source_ip,
                received,
                meta.hostname.clone().unwrap_or_default(),
                l.program,
                l.pid,
                l.event,
                l.outcome,
                l.user,
                l.target_user,
                l.client,
                l.port,
                l.method,
                l.command,
                country,
                country_code,
                received,
                body.trim(),
            ],
        )?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logtype::Registry;
    use chrono::Utc;

    // ─────────────────────────────────────────────────────────────────────────
    // bsd(line)
    // An RFC 3164 body as the syslog layer hands it over: the tag stripped from
    // raw, and put back in front in meta.body.
    // ─────────────────────────────────────────────────────────────────────────
    fn bsd(line: &str) -> (String, Meta) {
        let (tag_part, msg) = line.split_once(": ").unwrap_or(("", line));
        let tag = tag_part.split('[').next().unwrap_or("").to_string();
        let meta = Meta {
            source_ip: "10.0.0.20".into(),
            hostname: Some("web1".into()),
            tag: Some(tag),
            body: line.to_string(),
            received_at: Utc::now(),
        };
        (msg.to_string(), meta)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // parse(line)
    // Parses an RFC 3164 body as the ingest path would see it.
    // ─────────────────────────────────────────────────────────────────────────
    fn parse(line: &str) -> LinuxLine {
        let (raw, meta) = bsd(line);
        parse_line(&raw, &meta)
    }

    #[test]
    fn reads_sshd_logins() {
        let ok = parse("sshd[811]: Accepted publickey for yariv from 198.51.100.4 port 51234 ssh2: ED25519 SHA256:abc");
        assert_eq!((ok.program.as_str(), ok.pid), ("sshd", Some(811)));
        assert_eq!((ok.event, ok.outcome), ("login_ok", "success"));
        assert_eq!((ok.user.as_str(), ok.client.as_str(), ok.port), ("yariv", "198.51.100.4", Some(51234)));
        assert_eq!(ok.method, "publickey");

        let bad = parse("sshd[901]: Failed password for root from 203.0.113.9 port 40022 ssh2");
        assert_eq!((bad.event, bad.outcome, bad.user.as_str()), ("login_failed", "failure", "root"));
        assert_eq!(bad.method, "password");

        // "for invalid user" is still one failed login, for that user.
        let inv = parse("sshd[902]: Failed password for invalid user admin from 203.0.113.9 port 40023 ssh2");
        assert_eq!((inv.event, inv.user.as_str()), ("login_failed", "admin"));

        let kbd = parse("sshd-session[903]: Failed keyboard-interactive/pam for root from 2001:db8::7 port 5 ssh2");
        assert_eq!(
            (kbd.event, kbd.method.as_str(), kbd.client.as_str()),
            ("login_failed", "keyboard-interactive/pam", "2001:db8::7")
        );
    }

    #[test]
    fn reads_invalid_users_and_preauth_disconnects() {
        let inv = parse("sshd[1]: Invalid user oracle from 203.0.113.9 port 39000");
        assert_eq!(
            (inv.event, inv.user.as_str(), inv.client.as_str(), inv.port),
            ("invalid_user", "oracle", "203.0.113.9", Some(39000))
        );

        let empty = parse("sshd[1]: Invalid user  from 203.0.113.9 port 39001");
        assert_eq!((empty.event, empty.user.as_str()), ("invalid_user", ""));

        for (line, user) in [
            ("sshd[2]: Connection closed by authenticating user root 203.0.113.9 port 4 [preauth]", "root"),
            ("sshd[2]: Disconnected from invalid user test 203.0.113.9 port 4 [preauth]", "test"),
            ("sshd[2]: error: maximum authentication attempts exceeded for root from 203.0.113.9 port 4 ssh2 [preauth]", "root"),
            ("sshd[2]: Received disconnect from 203.0.113.9 port 4:11: Bye Bye [preauth]", ""),
            ("sshd[2]: Connection reset by 203.0.113.9 port 4 [preauth]", ""),
        ] {
            let l = parse(line);
            assert_eq!((l.event, l.outcome), ("preauth", "failure"), "{line}");
            assert_eq!((l.client.as_str(), l.port, l.user.as_str()), ("203.0.113.9", Some(4), user), "{line}");
        }

        // A normal logout is not an attack.
        let bye = parse("sshd[3]: Disconnected from user yariv 198.51.100.4 port 51234");
        assert_eq!(bye.event, "");
    }

    #[test]
    fn reads_sudo() {
        let ran = parse("sudo:    yariv : TTY=pts/0 ; PWD=/home/yariv ; USER=root ; COMMAND=/usr/bin/apt update");
        assert_eq!((ran.event, ran.outcome), ("sudo", "success"));
        assert_eq!((ran.user.as_str(), ran.target_user.as_str()), ("yariv", "root"));
        assert_eq!(ran.command, "/usr/bin/apt update");

        let refused = parse(
            "sudo:      bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        );
        assert_eq!((refused.event, refused.outcome), ("sudo_failed", "failure"));
        assert_eq!(
            (refused.method.as_str(), refused.command.as_str()),
            ("user NOT in sudoers", "/bin/cat /etc/shadow")
        );

        let wrong = parse(
            "sudo:    yariv : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/yariv ; USER=root ; COMMAND=/bin/ls",
        );
        assert_eq!((wrong.event, wrong.method.as_str()), ("sudo_failed", "3 incorrect password attempts"));

        // A command containing " ; " is kept whole.
        let semi = parse("sudo: yariv : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh -c echo a ; echo b");
        assert_eq!(semi.command, "/bin/sh -c echo a ; echo b");

        // sudo's own PAM session lines are plain text.
        let pam = parse("sudo: pam_unix(sudo:session): session opened for user root(uid=0) by yariv(uid=1000)");
        assert_eq!(pam.event, "");
    }

    #[test]
    fn reads_su_in_both_wordings() {
        let a = parse("su[77]: (to root) yariv on pts/0");
        assert_eq!((a.event, a.user.as_str(), a.target_user.as_str()), ("su", "yariv", "root"));
        let b = parse("su[77]: FAILED SU (to root) bob on pts/1");
        assert_eq!((b.event, b.outcome, b.user.as_str()), ("su_failed", "failure", "bob"));
        let c = parse("su[78]: Successful su for postgres by root");
        assert_eq!((c.event, c.user.as_str(), c.target_user.as_str()), ("su", "root", "postgres"));
        let d = parse("su[79]: FAILED su for root by bob");
        assert_eq!(d.event, "su_failed");
        assert_eq!(parse("su[79]: + pts/0 yariv:root").event, "");
    }

    #[test]
    fn counts_pam_failures_only_for_services_that_do_not_log_their_own() {
        let console = parse(
            "login[500]: pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  user=root",
        );
        assert_eq!(
            (console.event, console.method.as_str(), console.user.as_str()),
            ("login_failed", "login", "root")
        );

        let ftp = parse(
            "vsftpd[600]: pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=anon rhost=203.0.113.50",
        );
        assert_eq!((ftp.event, ftp.client.as_str()), ("login_failed", "203.0.113.50"));

        // sshd logs its own "Failed password" for the same attempt.
        let ssh = parse(
            "sshd[700]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=root",
        );
        assert_eq!(ssh.event, "");
    }

    #[test]
    fn reads_account_changes() {
        let add = parse(
            "useradd[900]: new user: name=deploy, UID=1001, GID=1001, home=/home/deploy, shell=/bin/bash, from=/dev/pts/0",
        );
        assert_eq!(
            (add.event, add.target_user.as_str(), add.method.as_str()),
            ("account", "deploy", "useradd")
        );
        assert_eq!(parse("userdel[901]: delete user 'deploy'").target_user, "deploy");
        let pw = parse("passwd[902]: pam_unix(passwd:chauthtok): password changed for yariv");
        assert_eq!((pw.event, pw.target_user.as_str()), ("account", "yariv"));
        assert_eq!(parse("usermod[903]: add 'deploy' to group 'sudo'").target_user, "deploy");
    }

    #[test]
    fn splits_an_rfc5424_header() {
        // <38>1 2026-10-31T10:00:00Z web1 sshd 1234 - - Failed password …
        let meta = Meta {
            source_ip: "10.0.0.20".into(),
            hostname: Some("web1".into()),
            tag: Some("sshd".into()),
            body: "sshd 1234 - - Failed password for root from 203.0.113.9 port 22 ssh2".into(),
            received_at: Utc::now(),
        };
        let l = parse_line("Failed password for root from 203.0.113.9 port 22 ssh2", &meta);
        assert_eq!((l.program.as_str(), l.pid), ("sshd", Some(1234)));
        assert_eq!((l.event, l.client.as_str()), ("login_failed", "203.0.113.9"));
    }

    #[test]
    fn keeps_every_line_and_geolocates_only_logins() {
        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        for line in [
            "CRON[1200]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)",
            "kernel: [12345.678] EXT4-fs (sda1): mounted filesystem",
            "sshd[901]: Failed password for root from 203.0.113.9 port 40022 ssh2",
        ] {
            let (raw, meta) = bsd(line);
            assert!(Linux.ingest(&raw, &meta, &conn).unwrap(), "should keep {line:?}");
        }
        let rows: Vec<(String, String, Option<String>, String)> = conn
            .prepare("SELECT program, event, country, raw FROM linux ORDER BY program")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(rows.len(), 3);
        assert_eq!((rows[0].0.as_str(), rows[0].1.as_str(), &rows[0].2), ("CRON", "", &None));
        assert_eq!(rows[1].0, "kernel");
        assert_eq!((rows[2].0.as_str(), rows[2].1.as_str()), ("sshd", "login_failed"));
        assert!(rows[2].2.is_some(), "a login attempt gets a country (even Unknown)");
        assert_eq!(rows[2].3, "sshd[901]: Failed password for root from 203.0.113.9 port 40022 ssh2");

        let (raw, meta) = bsd("   ");
        assert!(!Linux.ingest(&raw, &meta, &conn).unwrap());
    }
}
