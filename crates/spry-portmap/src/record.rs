//! A record of the mappings this process created, so that a later launch can
//! remove what a crashed run left behind.
//!
//! The file is plain text: a version line, then one tab-separated line per
//! mapping. It is read with a size limit, parsed strictly, and written
//! atomically (and private to the user on Unix).

use crate::upnp::Service;
use crate::{Error, Method, Protocol};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

const HEADER: &str = "spry-portmap 1";
/// Largest record file read.
pub const MAX_FILE: usize = 64 * 1024;
/// Most entries kept.
pub const MAX_ENTRIES: usize = 256;

/// One mapping this process created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub method: Method,
    pub protocol: Protocol,
    /// The gateway that granted it.
    pub gateway: Ipv4Addr,
    pub internal: SocketAddrV4,
    pub external_port: u16,
    /// Unix time the lease ends; `None` for a permanent UPnP lease.
    pub expires: Option<u64>,
    /// PCP mapping nonce, the only key that can renew or delete it.
    pub nonce: Option<[u8; 12]>,
    /// UPnP control URL and service.
    pub control: Option<String>,
    pub service: Option<Service>,
    /// UPnP description tag this process set.
    pub description: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<[u8; 12]> {
    if text.len() != 24 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 12];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// A value that may sit in one field: printable ASCII, spaces allowed, no tab.
fn field_safe(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && value.bytes().all(|b| (0x20..0x7f).contains(&b))
}

impl Entry {
    fn encode(&self) -> Result<String, Error> {
        let mut fields = vec![
            self.method.token().to_owned(),
            self.protocol.name().to_ascii_lowercase(),
            self.gateway.to_string(),
            self.internal.to_string(),
            self.external_port.to_string(),
            self.expires
                .map_or_else(|| "permanent".to_owned(), |at| at.to_string()),
        ];
        if let Some(nonce) = &self.nonce {
            fields.push(format!("nonce={}", hex(nonce)));
        }
        if let Some(service) = self.service {
            fields.push(format!("service={}", service.token()));
        }
        for (key, value) in [
            ("control", &self.control),
            ("description", &self.description),
        ] {
            if let Some(value) = value {
                if !field_safe(value) {
                    return Err(Error::Record("unsafe field"));
                }
                fields.push(format!("{key}={value}"));
            }
        }
        Ok(fields.join("\t"))
    }

    fn decode(line: &str) -> Result<Self, &'static str> {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 6 {
            return Err("short entry");
        }
        let method = Method::from_token(fields[0]).ok_or("bad method")?;
        let protocol = Protocol::parse(fields[1]).ok_or("bad protocol")?;
        let gateway = fields[2].parse().map_err(|_| "bad gateway")?;
        let internal: SocketAddrV4 = fields[3].parse().map_err(|_| "bad internal endpoint")?;
        let external_port: u16 = fields[4].parse().map_err(|_| "bad external port")?;
        if external_port == 0 || internal.port() == 0 {
            return Err("bad port");
        }
        let expires = match fields[5] {
            "permanent" => None,
            at => Some(at.parse().map_err(|_| "bad expiry")?),
        };
        let mut entry = Entry {
            method,
            protocol,
            gateway,
            internal,
            external_port,
            expires,
            nonce: None,
            control: None,
            service: None,
            description: None,
        };
        for field in &fields[6..] {
            let (key, value) = field.split_once('=').ok_or("bad field")?;
            if !field_safe(value) {
                return Err("bad field");
            }
            let slot_taken = match key {
                "nonce" => entry
                    .nonce
                    .replace(unhex(value).ok_or("bad nonce")?)
                    .is_some(),
                "service" => entry
                    .service
                    .replace(Service::from_token(value).ok_or("bad service")?)
                    .is_some(),
                "control" => entry.control.replace(value.to_owned()).is_some(),
                "description" => entry.description.replace(value.to_owned()).is_some(),
                _ => return Err("unknown field"),
            };
            if slot_taken {
                return Err("repeated field");
            }
        }
        let complete = match method {
            Method::Pcp => entry.nonce.is_some(),
            Method::NatPmp => true,
            Method::Upnp => {
                entry.control.is_some() && entry.service.is_some() && entry.description.is_some()
            }
        };
        if !complete {
            return Err("incomplete entry");
        }
        if entry.expires.is_none() && method != Method::Upnp {
            return Err("only UPnP leases can be permanent");
        }
        Ok(entry)
    }
}

/// Encode entries as a record file.
pub fn encode(entries: &[Entry]) -> Result<String, Error> {
    if entries.len() > MAX_ENTRIES {
        return Err(Error::Record("too many entries"));
    }
    let mut text = format!("{HEADER}\n");
    for entry in entries {
        text.push_str(&entry.encode()?);
        text.push('\n');
    }
    if text.len() > MAX_FILE {
        return Err(Error::Record("file too large"));
    }
    Ok(text)
}

/// Decode a record file.
pub fn decode(text: &str) -> Result<Vec<Entry>, Error> {
    if text.len() > MAX_FILE {
        return Err(Error::Record("file too large"));
    }
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err(Error::Record("unknown version"));
    }
    let mut entries = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        if entries.len() >= MAX_ENTRIES {
            return Err(Error::Record("too many entries"));
        }
        entries.push(Entry::decode(line).map_err(Error::Record)?);
    }
    Ok(entries)
}

/// The record file and its entries.
#[derive(Debug)]
pub struct Ledger {
    path: PathBuf,
    entries: Vec<Entry>,
}

impl Ledger {
    /// Load the record at `path`; a missing file is an empty record.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        let entries = match std::fs::File::open(&path) {
            Ok(file) => {
                let mut text = String::new();
                file.take(MAX_FILE as u64 + 1)
                    .read_to_string(&mut text)
                    .map_err(|_| Error::Record("unreadable"))?;
                decode(&text)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(Error::Io(error.kind())),
        };
        Ok(Self { path, entries })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Add or replace (same method, protocol, gateway and external port) an
    /// entry, and save.
    pub fn record(&mut self, entry: Entry) -> Result<(), Error> {
        let mut entries = self.entries.clone();
        entries.retain(|known| !same_mapping(known, &entry));
        entries.push(entry);
        self.save(entries)
    }

    /// Drop entries for which `keep` is false, and save.
    pub fn retain(&mut self, keep: impl FnMut(&Entry) -> bool) -> Result<(), Error> {
        let mut entries = self.entries.clone();
        entries.retain(keep);
        self.save(entries)
    }

    fn save(&mut self, entries: Vec<Entry>) -> Result<(), Error> {
        let text = encode(&entries)?;
        let mut temporary = self.path.clone().into_os_string();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &self.path)?;
        self.entries = entries;
        Ok(())
    }
}

/// Whether two entries describe the same mapping on the gateway.
pub fn same_mapping(a: &Entry, b: &Entry) -> bool {
    a.method == b.method
        && a.protocol == b.protocol
        && a.gateway == b.gateway
        && a.external_port == b.external_port
        && a.internal == b.internal
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<Entry> {
        vec![
            Entry {
                method: Method::Pcp,
                protocol: Protocol::Udp,
                gateway: Ipv4Addr::new(192, 168, 1, 1),
                internal: "192.168.1.20:3478".parse().unwrap(),
                external_port: 3478,
                expires: Some(1_800_000_000),
                nonce: Some(*b"0123456789ab"),
                control: None,
                service: None,
                description: None,
            },
            Entry {
                method: Method::Upnp,
                protocol: Protocol::Tcp,
                gateway: Ipv4Addr::new(192, 168, 1, 1),
                internal: "192.168.1.20:3478".parse().unwrap(),
                external_port: 40000,
                expires: None,
                nonce: None,
                control: Some("http://192.168.1.1:5000/ctl/IPConn".into()),
                service: Some(Service::WanIp1),
                description: Some("spry relay 1a2b".into()),
            },
            Entry {
                method: Method::NatPmp,
                protocol: Protocol::Udp,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                internal: "10.0.0.5:50000".parse().unwrap(),
                external_port: 50001,
                expires: Some(1_800_000_100),
                nonce: None,
                control: None,
                service: None,
                description: None,
            },
        ]
    }

    #[test]
    fn round_trips_exactly() {
        let text = encode(&entries()).unwrap();
        assert_eq!(
            text.lines().nth(1).unwrap(),
            "pcp\tudp\t192.168.1.1\t192.168.1.20:3478\t3478\t1800000000\tnonce=303132333435363738396162"
        );
        assert_eq!(decode(&text).unwrap(), entries());
    }

    #[test]
    fn refuses_malformed_records() {
        let good = encode(&entries()).unwrap();
        let bad = [
            "spry-portmap 2\n".to_owned(),
            good.replace("nonce=3031", "nonce=zz31"),
            good.replace("\tnonce=303132333435363738396162", ""),
            good.replace("service=WANIPConnection:1", "service=Other:1"),
            good.replace("pcp\tudp", "pcp\tsctp"),
            good.replace("1800000000", "permanent"),
            good.replace("\t3478\t1800000000", "\t0\t1800000000"),
            good.replace(
                "description=spry relay 1a2b",
                "description=spry relay 1a2b\tdescription=x",
            ),
            good.replace("description=", "colour="),
            format!("{good}{}", "x".repeat(MAX_FILE)),
        ];
        for text in bad {
            assert!(matches!(decode(&text), Err(Error::Record(_))), "{text}");
        }
        let mut unsafe_entry = entries();
        unsafe_entry[1].description = Some("tab\there".into());
        assert_eq!(encode(&unsafe_entry), Err(Error::Record("unsafe field")));
    }

    #[test]
    fn ledger_saves_atomically_and_reloads() {
        let directory =
            std::env::temp_dir().join(format!("spry-portmap-ledger-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("mappings");
        let _ = std::fs::remove_file(&path);
        let mut ledger = Ledger::load(&path).unwrap();
        assert!(ledger.entries().is_empty());
        for entry in entries() {
            ledger.record(entry).unwrap();
        }
        ledger.record(entries()[0].clone()).unwrap();
        assert_eq!(Ledger::load(&path).unwrap().entries().len(), 3);
        ledger.retain(|entry| entry.method != Method::Pcp).unwrap();
        assert_eq!(Ledger::load(&path).unwrap().entries().len(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
