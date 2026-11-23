#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use spry_portmap::{http, natpmp, pcp, record, route, upnp, xml};

// Everything a router, a gateway on the local network or the mapping record
// file can hand the port mapper. The parsers must refuse, never panic, hang
// or allocate beyond their stated bounds.
fuzz_target!(|data: &[u8]| {
    // Binary gateway replies.
    let _ = pcp::decode(data);
    let _ = natpmp::decode(data);

    // SSDP search replies and SOAP bodies arrive as bytes.
    if let Ok(location) = upnp::parse_search_response(data) {
        let _ = location.socket();
    }
    for status in [200, 500] {
        let _ = upnp::parse_soap(status, data, "AddPortMapping");
        let _ = upnp::parse_soap(status, data, "GetExternalIPAddress");
    }

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(root) = xml::parse(text) {
        let _ = root.child("device");
        let _ = root.child_text("URLBase");
        assert!(root.descendants("service").len() <= xml::MAX_ELEMENTS);
    }
    let base = http::Url::parse("http://192.0.2.1:5000/root.xml").expect("literal");
    let _ = upnp::parse_description(text, &base);
    if let Ok(url) = http::Url::parse(text) {
        let _ = url.socket();
    }
    if let Ok(joined) = base.join(text) {
        let _ = joined.socket();
    }
    let _ = upnp::Service::from_urn(text);
    let _ = upnp::Service::from_token(text);

    // The saved mapping record and the platform routing tables.
    if let Ok(entries) = record::decode(text) {
        let _ = record::encode(&entries);
    }
    let _ = route::parse_proc_net_route(text);
    let _ = route::parse_bsd_route_get(text);
    let _ = route::parse_windows_route_print(text);
});
