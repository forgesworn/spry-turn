//! UPnP Internet Gateway Device: SSDP discovery, device description and the
//! WANIPConnection (v1, v2) and WANPPPConnection (v1) SOAP actions this
//! crate needs.
//!
//! Only the default gateway is trusted: an SSDP answer counts only when it
//! comes from the gateway's address and its description and control URLs
//! name that same address.

use crate::http::{self, Url};
use crate::{Error, Method, Protocol, xml};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

/// The SSDP multicast group and port.
pub const SSDP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
/// Largest device description accepted.
pub const MAX_DESCRIPTION: usize = 64 * 1024;
/// Largest SOAP reply accepted.
pub const MAX_SOAP: usize = 16 * 1024;
/// Largest SSDP datagram accepted.
pub const MAX_SSDP: usize = 2048;
/// SSDP datagrams read per discovery before giving up.
const MAX_SSDP_REPLIES: usize = 64;
/// Device descriptions fetched per discovery.
const MAX_DESCRIPTIONS: usize = 4;

/// Device types searched for, IGDv2 first.
pub const SEARCH_TARGETS: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
];

/// A WAN connection service, in order of preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Service {
    WanIp2,
    WanIp1,
    WanPpp1,
}

impl Service {
    pub const ALL: [Service; 3] = [Service::WanIp2, Service::WanIp1, Service::WanPpp1];

    pub const fn urn(self) -> &'static str {
        match self {
            Self::WanIp2 => "urn:schemas-upnp-org:service:WANIPConnection:2",
            Self::WanIp1 => "urn:schemas-upnp-org:service:WANIPConnection:1",
            Self::WanPpp1 => "urn:schemas-upnp-org:service:WANPPPConnection:1",
        }
    }
    pub fn from_urn(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|service| service.urn() == value)
    }
    /// Short form used in the record file.
    pub const fn token(self) -> &'static str {
        match self {
            Self::WanIp2 => "WANIPConnection:2",
            Self::WanIp1 => "WANIPConnection:1",
            Self::WanPpp1 => "WANPPPConnection:1",
        }
    }
    pub fn from_token(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|service| service.token() == value)
    }
    /// IGDv2 services offer `AddAnyPortMapping`.
    pub const fn is_v2(self) -> bool {
        matches!(self, Self::WanIp2)
    }
}

/// A gateway's control endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gateway {
    pub control: Url,
    pub service: Service,
}

/// An SSDP M-SEARCH request.
pub fn search_request(host: SocketAddrV4, target: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {host}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {target}\r\n\r\n"
    )
}

/// The `LOCATION` of an SSDP search answer.
pub fn parse_search_response(bytes: &[u8]) -> Result<Url, &'static str> {
    if bytes.len() > MAX_SSDP {
        return Err("oversized");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "not text")?;
    let head = text.trim_end_matches("\r\n");
    let (status, headers) = http::parse_head(head)?;
    if status != 200 {
        return Err("not a search answer");
    }
    let mut locations = headers.iter().filter(|(name, _)| name == "location");
    let (_, location) = locations.next().ok_or("no location")?;
    if locations.next().is_some() {
        return Err("more than one location");
    }
    Url::parse(location)
}

/// Pick the preferred WAN connection service from a device description.
pub fn parse_description(document: &str, location: &Url) -> Result<Gateway, &'static str> {
    let root = xml::parse(document)?;
    if root.name != "root" {
        return Err("not a device description");
    }
    let base = match root.child_text("URLBase").filter(|base| !base.is_empty()) {
        Some(base) => Url::parse(base)?,
        None => location.clone(),
    };
    let mut best: Option<Gateway> = None;
    for service in root.descendants("service") {
        let Some(kind) = service
            .child_text("serviceType")
            .and_then(Service::from_urn)
        else {
            continue;
        };
        if best.as_ref().is_some_and(|best| best.service <= kind) {
            continue;
        }
        let Some(control) = service.child_text("controlURL") else {
            continue;
        };
        best = Some(Gateway {
            control: base.join(control)?,
            service: kind,
        });
    }
    best.ok_or("no WAN connection service")
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// A SOAP request envelope.
pub fn soap_envelope(service: Service, action: &str, args: &[(&str, String)]) -> String {
    let mut body = format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{}\">",
        service.urn()
    );
    for (name, value) in args {
        body.push_str(&format!("<{name}>{}</{name}>", escape(value)));
    }
    body.push_str(&format!("</u:{action}></s:Body></s:Envelope>\r\n"));
    body
}

/// A SOAP call that did not succeed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SoapError {
    /// A UPnP error code from a SOAP fault.
    Fault(u16),
    Malformed(&'static str),
}

/// Parse a SOAP reply into its output arguments.
pub fn parse_soap(
    status: u16,
    body: &[u8],
    action: &str,
) -> Result<Vec<(String, String)>, SoapError> {
    let text = std::str::from_utf8(body).map_err(|_| SoapError::Malformed("not text"))?;
    let root = xml::parse(text).map_err(SoapError::Malformed)?;
    if root.name != "Envelope" {
        return Err(SoapError::Malformed("not a SOAP envelope"));
    }
    let body = root
        .child("Body")
        .ok_or(SoapError::Malformed("no SOAP body"))?;
    if status == 200 {
        let name = format!("{action}Response");
        let response = body
            .child(&name)
            .ok_or(SoapError::Malformed("no action response"))?;
        return Ok(response
            .children
            .iter()
            .map(|child| (child.name.clone(), child.text.trim().to_owned()))
            .collect());
    }
    let fault = body
        .child("Fault")
        .ok_or(SoapError::Malformed("unexpected HTTP status"))?;
    let code = fault
        .descendants("UPnPError")
        .first()
        .and_then(|error| error.child_text("errorCode"))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(SoapError::Malformed("fault without a UPnP error code"))?;
    Err(SoapError::Fault(code))
}

/// Words for a UPnP IGD error code.
pub const fn reason(code: u16) -> &'static str {
    match code {
        401 => "invalid action",
        402 => "invalid arguments",
        501 => "action failed",
        606 => "action not authorised",
        714 => "no such entry",
        715 => "wildcard not permitted in source address",
        716 => "wildcard not permitted in external port",
        718 => "conflict with another mapping",
        724 => "external and internal ports must match",
        725 => "only permanent leases supported",
        726 => "remote host must be a wildcard",
        727 => "external port must be a wildcard",
        728 => "no port maps available",
        729 => "conflict with another mechanism",
        732 => "wildcard not permitted in internal port",
        _ => "unknown error",
    }
}

pub const NO_SUCH_ENTRY: u16 = 714;
pub const ONLY_PERMANENT: u16 = 725;

/// A port mapping as the gateway reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub internal: SocketAddrV4,
    pub description: String,
    pub lease: u32,
    pub enabled: bool,
}

fn argument<'a>(args: &'a [(String, String)], name: &str) -> Result<&'a str, Error> {
    args.iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .ok_or(Error::Malformed("missing SOAP argument"))
}

/// A discovered gateway with the deadline used for each call.
#[derive(Clone, Debug)]
pub(crate) struct Igd {
    pub gateway: Gateway,
    pub timeout: Duration,
}

impl Igd {
    fn call(&self, action: &str, args: &[(&str, String)]) -> Result<Vec<(String, String)>, Error> {
        let body = soap_envelope(self.gateway.service, action, args);
        let soap_action = format!("\"{}#{action}\"", self.gateway.service.urn());
        let response = http::request(
            &self.gateway.control,
            "POST",
            &[
                ("Content-Type", "text/xml; charset=\"utf-8\""),
                ("SOAPAction", &soap_action),
            ],
            body.as_bytes(),
            MAX_SOAP,
            self.timeout,
        )?;
        parse_soap(response.status, &response.body, action).map_err(|error| match error {
            SoapError::Fault(code) => Error::Refused {
                method: Method::Upnp,
                code,
                reason: reason(code),
            },
            SoapError::Malformed(reason) => Error::Malformed(reason),
        })
    }

    pub(crate) fn external_address(&self) -> Result<Ipv4Addr, Error> {
        let args = self.call("GetExternalIPAddress", &[])?;
        argument(&args, "NewExternalIPAddress")?
            .parse()
            .map_err(|_| Error::Malformed("no external address"))
    }

    fn mapping_args(
        protocol: Protocol,
        external_port: u16,
        internal: SocketAddrV4,
        description: &str,
        lease: u32,
    ) -> Vec<(&'static str, String)> {
        vec![
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external_port.to_string()),
            ("NewProtocol", protocol.name().to_owned()),
            ("NewInternalPort", internal.port().to_string()),
            ("NewInternalClient", internal.ip().to_string()),
            ("NewEnabled", "1".to_owned()),
            ("NewPortMappingDescription", description.to_owned()),
            ("NewLeaseDuration", lease.to_string()),
        ]
    }

    /// `AddPortMapping` with an exact external port; also renews.
    pub(crate) fn add(
        &self,
        protocol: Protocol,
        external_port: u16,
        internal: SocketAddrV4,
        description: &str,
        lease: u32,
    ) -> Result<(), Error> {
        let args = Self::mapping_args(protocol, external_port, internal, description, lease);
        self.call("AddPortMapping", &args).map(|_| ())
    }

    /// IGDv2 `AddAnyPortMapping`: the gateway may pick another external port.
    pub(crate) fn add_any(
        &self,
        protocol: Protocol,
        external_port: u16,
        internal: SocketAddrV4,
        description: &str,
        lease: u32,
    ) -> Result<u16, Error> {
        let args = Self::mapping_args(protocol, external_port, internal, description, lease);
        let reply = self.call("AddAnyPortMapping", &args)?;
        argument(&reply, "NewReservedPort")?
            .parse()
            .ok()
            .filter(|&port| port != 0)
            .ok_or(Error::Malformed("no reserved port"))
    }

    pub(crate) fn entry(&self, protocol: Protocol, external_port: u16) -> Result<Entry, Error> {
        let args = [
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external_port.to_string()),
            ("NewProtocol", protocol.name().to_owned()),
        ];
        let reply = self.call("GetSpecificPortMappingEntry", &args)?;
        let port = argument(&reply, "NewInternalPort")?
            .parse()
            .map_err(|_| Error::Malformed("bad internal port"))?;
        let client: Ipv4Addr = argument(&reply, "NewInternalClient")?
            .parse()
            .map_err(|_| Error::Malformed("bad internal client"))?;
        let lease = argument(&reply, "NewLeaseDuration")?
            .parse()
            .map_err(|_| Error::Malformed("bad lease"))?;
        let enabled = matches!(argument(&reply, "NewEnabled")?, "1" | "true" | "yes");
        Ok(Entry {
            internal: SocketAddrV4::new(client, port),
            description: argument(&reply, "NewPortMappingDescription")?.to_owned(),
            lease,
            enabled,
        })
    }

    pub(crate) fn delete(&self, protocol: Protocol, external_port: u16) -> Result<(), Error> {
        let args = [
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external_port.to_string()),
            ("NewProtocol", protocol.name().to_owned()),
        ];
        self.call("DeletePortMapping", &args).map(|_| ())
    }
}

fn fetch_gateway(location: &Url, gateway: Ipv4Addr, timeout: Duration) -> Result<Gateway, Error> {
    let response = http::request(location, "GET", &[], &[], MAX_DESCRIPTION, timeout)?;
    if response.status != 200 {
        return Err(Error::Malformed("description unavailable"));
    }
    let text = std::str::from_utf8(&response.body).map_err(|_| Error::Malformed("not text"))?;
    let found = parse_description(text, location).map_err(|reason| match reason {
        "no WAN connection service" => Error::NoIgd,
        reason => Error::Malformed(reason),
    })?;
    if found.control.host != gateway {
        return Err(Error::OffLan);
    }
    Ok(found)
}

/// Search for the gateway's IGD and read its description.
///
/// `target` is normally [`SSDP`]; a multicast search is also sent straight to
/// the gateway's port 1900. Only answers from `gateway` whose description
/// and control URLs name `gateway` are used.
pub(crate) fn discover(
    gateway: Ipv4Addr,
    local: Ipv4Addr,
    target: SocketAddrV4,
    budget: Duration,
    http_timeout: Duration,
) -> Result<Gateway, Error> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.bind(&SocketAddr::from((local, 0)).into())?;
    let mut destinations = vec![target];
    if target.ip().is_multicast() {
        socket.set_multicast_if_v4(&local)?;
        socket.set_multicast_ttl_v4(2)?;
        destinations.push(SocketAddrV4::new(gateway, SSDP.port()));
    }
    let socket: UdpSocket = socket.into();
    let send = |socket: &UdpSocket| {
        for destination in &destinations {
            for search in SEARCH_TARGETS {
                // A lost datagram is covered by the second round.
                let _ =
                    socket.send_to(search_request(*destination, search).as_bytes(), destination);
            }
        }
    };
    send(&socket);
    let start = Instant::now();
    let deadline = start + budget;
    let mut resent = false;
    let mut tried: Vec<Url> = Vec::new();
    let mut failure = Error::NoAnswer;
    let mut buffer = [0u8; MAX_SSDP + 1];
    let mut replies = 0;
    while replies < MAX_SSDP_REPLIES && tried.len() < MAX_DESCRIPTIONS {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if !resent && now >= start + budget / 3 {
            send(&socket);
            resent = true;
        }
        let wait = (deadline - now)
            .min(budget / 3)
            .max(Duration::from_millis(1));
        socket.set_read_timeout(Some(wait))?;
        let (size, from) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        replies += 1;
        if from.ip() != std::net::IpAddr::V4(gateway) {
            continue;
        }
        let location = match parse_search_response(&buffer[..size]) {
            Ok(location) => location,
            Err(reason) => {
                failure = Error::Malformed(reason);
                continue;
            }
        };
        if location.host != gateway {
            failure = Error::OffLan;
            continue;
        }
        if tried.contains(&location) {
            continue;
        }
        tried.push(location.clone());
        let left = deadline.saturating_duration_since(Instant::now());
        match fetch_gateway(
            &location,
            gateway,
            http_timeout.min(left.max(Duration::from_millis(1))),
        ) {
            Ok(found) => return Ok(found),
            Err(error) => failure = error,
        }
    }
    Err(failure)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>
<device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/ctl/L3F</controlURL></service></serviceList>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
<serviceList>
<service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType><controlURL>/ctl/PPPConn</controlURL></service>
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>ctl/IPConn</controlURL></service>
</serviceList></device></deviceList></device></deviceList></device></root>"#;

    #[test]
    fn search_request_is_exact() {
        assert_eq!(
            search_request(SSDP, SEARCH_TARGETS[1]),
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n\
             ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
        );
    }

    #[test]
    fn reads_search_answers() {
        let answer = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\nST: x\r\n\r\n";
        assert_eq!(
            parse_search_response(answer).unwrap().to_string(),
            "http://192.168.1.1:5000/rootDesc.xml"
        );
        assert_eq!(
            parse_search_response(b"NOTIFY * HTTP/1.1\r\nHOST: x\r\n\r\n"),
            Err("not an HTTP response")
        );
        assert_eq!(
            parse_search_response(b"HTTP/1.1 200 OK\r\nST: x\r\n\r\n"),
            Err("no location")
        );
        assert_eq!(
            parse_search_response(b"HTTP/1.1 200 OK\r\nLOCATION: http://10.0.0.1/\r\nLOCATION: http://10.0.0.2/\r\n\r\n"),
            Err("more than one location")
        );
        assert_eq!(
            parse_search_response(b"HTTP/1.1 200 OK\r\nLOCATION: http://router.lan/\r\n\r\n"),
            Err("host is not an IPv4 literal")
        );
        assert_eq!(
            parse_search_response(&[b'a'; MAX_SSDP + 1]),
            Err("oversized")
        );
    }

    #[test]
    fn prefers_wan_ip_and_resolves_control_urls() {
        let location = Url::parse("http://192.168.1.1:5000/dev/rootDesc.xml").unwrap();
        let found = parse_description(DESCRIPTION, &location).unwrap();
        assert_eq!(found.service, Service::WanIp1);
        assert_eq!(
            found.control.to_string(),
            "http://192.168.1.1:5000/dev/ctl/IPConn"
        );
        let based = DESCRIPTION.replace(
            "<specVersion>",
            "<URLBase>http://192.168.1.1:49000/</URLBase><specVersion>",
        );
        assert_eq!(
            parse_description(&based, &location).unwrap().control.port,
            49000
        );
        let ppp_only = DESCRIPTION.replace("WANIPConnection", "WANIPv6FirewallControl");
        assert_eq!(
            parse_description(&ppp_only, &location).unwrap().service,
            Service::WanPpp1
        );
        let none = ppp_only.replace("WANPPPConnection", "Other");
        assert_eq!(
            parse_description(&none, &location),
            Err("no WAN connection service")
        );
        assert_eq!(
            parse_description("<scpd/>", &location),
            Err("not a device description")
        );
    }

    #[test]
    fn envelope_escapes_values() {
        let body = soap_envelope(
            Service::WanIp1,
            "AddPortMapping",
            &[("NewPortMappingDescription", "a<b&\"c\"".into())],
        );
        assert!(body.contains(
            "<NewPortMappingDescription>a&lt;b&amp;&quot;c&quot;</NewPortMappingDescription>"
        ));
        assert!(body.contains("xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\""));
        assert!(xml::parse(&body).is_ok());
    }

    #[test]
    fn reads_responses_and_faults() {
        let ok = br#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="x"><NewExternalIPAddress> 198.51.100.7 </NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"#;
        assert_eq!(
            parse_soap(200, ok, "GetExternalIPAddress").unwrap(),
            vec![("NewExternalIPAddress".to_owned(), "198.51.100.7".to_owned())]
        );
        assert_eq!(
            parse_soap(200, ok, "AddPortMapping"),
            Err(SoapError::Malformed("no action response"))
        );
        let fault = br#"<s:Envelope xmlns:s="x"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"#;
        assert_eq!(
            parse_soap(500, fault, "AddPortMapping"),
            Err(SoapError::Fault(ONLY_PERMANENT))
        );
        assert_eq!(
            parse_soap(500, ok, "GetExternalIPAddress"),
            Err(SoapError::Malformed("unexpected HTTP status"))
        );
        assert_eq!(
            parse_soap(200, b"<html/>", "X"),
            Err(SoapError::Malformed("not a SOAP envelope"))
        );
        assert_eq!(
            parse_soap(200, &[0xff, 0xfe], "X"),
            Err(SoapError::Malformed("not text"))
        );
    }
}
