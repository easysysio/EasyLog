// =============================================================================
// auth.rs — admin account, password hashing, and the cookie-signing key
//
// EasyLog gates its web UI behind a single admin account created on first run
// (GUI setup). Passwords are bcrypt-hashed and stored in the `users` table.
// Sessions are stateless signed cookies; the signing key is generated once and
// persisted (hex) in `app_meta`, so logins survive restarts. The syslog
// listeners are NOT affected by auth — only the web UI is.
// =============================================================================

use anyhow::{Result, bail};
use axum_extra::extract::cookie::Key;
use duckdb::{Connection, params};

// ─────────────────────────────────────────────────────────────────────────────
// init_schema(conn)
// Creates the `users` and `app_meta` tables if absent.
// ─────────────────────────────────────────────────────────────────────────────
pub fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            username      VARCHAR PRIMARY KEY,
            password_hash VARCHAR NOT NULL,
            created_at    TIMESTAMP DEFAULT now()
        );
        CREATE TABLE IF NOT EXISTS app_meta (
            name  VARCHAR PRIMARY KEY,
            value VARCHAR NOT NULL
        );
        "#,
    )?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// admin_exists(conn)
// Whether any user has been created yet (drives the first-run setup flow).
// ─────────────────────────────────────────────────────────────────────────────
pub fn admin_exists(conn: &Connection) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT count(*) FROM users")?;
    let mut rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
    Ok(rows.next().transpose()?.unwrap_or(0) > 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// create_admin(conn, username, password)
// Creates the admin account (bcrypt-hashed). Rejects empty username, a short
// password, or a second admin.
// ─────────────────────────────────────────────────────────────────────────────
pub fn create_admin(conn: &Connection, username: &str, password: &str) -> Result<()> {
    let username = username.trim();
    if username.is_empty() {
        bail!("username is required");
    }
    if password.len() < 8 {
        bail!("password must be at least 8 characters");
    }
    if admin_exists(conn)? {
        bail!("an admin account already exists");
    }
    let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        params![username, hash],
    )?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// verify_credentials(conn, username, password)
// Returns true iff the username exists and the password matches its bcrypt hash.
// ─────────────────────────────────────────────────────────────────────────────
pub fn verify_credentials(conn: &Connection, username: &str, password: &str) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT password_hash FROM users WHERE username = ?")?;
    let mut rows = stmt.query_map(params![username.trim()], |r| r.get::<_, String>(0))?;
    match rows.next().transpose()? {
        Some(hash) => Ok(bcrypt::verify(password, &hash).unwrap_or(false)),
        None => Ok(false),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// load_or_create_cookie_key(conn)
// Loads the persisted cookie-signing key (hex in app_meta), generating and
// storing a fresh one on first run so signed session cookies survive restarts.
// ─────────────────────────────────────────────────────────────────────────────
pub fn load_or_create_cookie_key(conn: &Connection) -> Result<Key> {
    let existing: Option<String> = {
        let mut stmt = conn.prepare("SELECT value FROM app_meta WHERE name = 'cookie_key'")?;
        let mut rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.next().transpose()?
    };

    if let Some(hex) = existing {
        if let Some(bytes) = from_hex(&hex) {
            if bytes.len() >= 64 {
                return Ok(Key::from(&bytes));
            }
        }
    }

    let key = Key::generate();
    conn.execute(
        "INSERT INTO app_meta (name, value) VALUES ('cookie_key', ?) \
         ON CONFLICT (name) DO UPDATE SET value = excluded.value",
        params![to_hex(key.master())],
    )?;
    Ok(key)
}

// Hex-encode bytes (used to persist the binary signing key as VARCHAR).
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// Decode a hex string back to bytes; None if malformed.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
