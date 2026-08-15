// =============================================================================
// geo.rs — IP geolocation (country) from a local MaxMind-format database
//
// Resolves a client IP to an ISO-2 country code + name using a bundled DB-IP
// Lite country database (embedded in the binary), or an external .mmdb if
// `geo_db_path` is configured. Lookups happen at ingest time so dashboards can
// simply GROUP BY country. Everything is offline — no external API calls.
//
// Attribution: bundled database is "IP Geolocation by DB-IP" (https://db-ip.com),
// licensed CC BY 4.0.
// =============================================================================

use std::net::IpAddr;
use std::sync::OnceLock;

use maxminddb::{Reader, geoip2};

// Embedded DB-IP Lite country database (CC BY 4.0).
static EMBEDDED_DB: &[u8] = include_bytes!("../assets/geo/dbip-country-lite.mmdb");

// The loaded reader, or None if no database could be loaded (geo disabled).
static READER: OnceLock<Option<Reader<Vec<u8>>>> = OnceLock::new();

// ─────────────────────────────────────────────────────────────────────────────
// init(geo_db_path)
// Loads the geolocation database once at startup: the external file at
// `geo_db_path` if set (falling back to the embedded DB on error), otherwise the
// embedded DB-IP Lite country database.
// ─────────────────────────────────────────────────────────────────────────────
pub fn init(geo_db_path: &str) {
    let path = geo_db_path.trim();
    let reader = if !path.is_empty() {
        match Reader::open_readfile(path) {
            Ok(r) => {
                tracing::info!("geo: loaded database {path}");
                Some(r)
            }
            Err(e) => {
                tracing::warn!("geo: could not load {path} ({e}); using the bundled database");
                embedded()
            }
        }
    } else {
        embedded()
    };
    let _ = READER.set(reader);
}

fn embedded() -> Option<Reader<Vec<u8>>> {
    match Reader::from_source(EMBEDDED_DB.to_vec()) {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::error!("geo: bundled database failed to load: {e}");
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// lookup(ip)
// Resolves a client IP string to (ISO-2 code, display name). An empty code means
// "no country": private/loopback ranges → "Private network"; anything else that
// can't be resolved → "Unknown".
// ─────────────────────────────────────────────────────────────────────────────
pub fn lookup(ip: &str) -> (String, String) {
    let Ok(addr) = ip.trim().parse::<IpAddr>() else {
        return (String::new(), "Unknown".to_string());
    };
    if is_private(&addr) {
        return (String::new(), "Private network".to_string());
    }
    let Some(Some(reader)) = READER.get().map(Option::as_ref) else {
        return (String::new(), "Unknown".to_string());
    };
    match reader.lookup::<geoip2::Country>(addr) {
        Ok(rec) => {
            let country = rec.country.as_ref();
            let code = country.and_then(|c| c.iso_code).unwrap_or("").to_string();
            let name = country
                .and_then(|c| c.names.as_ref())
                .and_then(|n| n.get("en").copied())
                .unwrap_or("Unknown")
                .to_string();
            if code.is_empty() {
                (String::new(), "Unknown".to_string())
            } else {
                (code, name)
            }
        }
        Err(_) => (String::new(), "Unknown".to_string()),
    }
}

// True for addresses that have no meaningful public geolocation.
fn is_private(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_bogus_addresses_have_no_country() {
        // No reader is initialized in this test, but private/unparseable inputs
        // are handled before any lookup, so they resolve deterministically.
        assert_eq!(lookup("10.0.0.1"), (String::new(), "Private network".to_string()));
        assert_eq!(lookup("192.168.1.20"), (String::new(), "Private network".to_string()));
        assert_eq!(lookup("127.0.0.1"), (String::new(), "Private network".to_string()));
        assert_eq!(lookup("::1"), (String::new(), "Private network".to_string()));
        assert_eq!(lookup("not-an-ip"), (String::new(), "Unknown".to_string()));
    }

    #[test]
    fn resolves_a_public_ip_from_the_bundled_database() {
        // Load the embedded DB-IP database and resolve a well-known public IP.
        init("");
        let (code, name) = lookup("8.8.8.8");
        assert!(!code.is_empty(), "expected a country code for 8.8.8.8");
        assert_ne!(name, "Unknown");
    }
}
