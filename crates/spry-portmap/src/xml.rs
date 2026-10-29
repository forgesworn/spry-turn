//! A small, bounded XML reader for UPnP device descriptions and SOAP replies.
//!
//! It builds a tree of elements with their local names (namespace prefixes
//! dropped) and text. Attributes are checked for shape and discarded. A
//! document type declaration, any entity beyond the five predefined ones and
//! numeric references, and anything past the depth, element or text limits
//! are refused. There is no DTD, entity expansion or external fetching.

/// Largest nesting depth accepted.
pub const MAX_DEPTH: usize = 24;
/// Most elements accepted in one document.
pub const MAX_ELEMENTS: usize = 2048;
/// Most text bytes kept for one element.
pub const MAX_TEXT: usize = 4096;

/// One element.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Element {
    /// Local name, without any namespace prefix.
    pub name: String,
    pub children: Vec<Element>,
    /// Decoded character data directly inside this element.
    pub text: String,
}

impl Element {
    /// First direct child with this local name.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|child| child.name == name)
    }
    /// Trimmed text of the first direct child with this local name.
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|child| child.text.trim())
    }
    /// Every element below this one with this local name, in document order.
    pub fn descendants<'a>(&'a self, name: &str) -> Vec<&'a Element> {
        let mut found = Vec::new();
        let mut stack: Vec<&Element> = self.children.iter().rev().collect();
        while let Some(element) = stack.pop() {
            if element.name == name {
                found.push(element);
            }
            stack.extend(element.children.iter().rev());
        }
        found
    }
}

fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|at| from + at)
}

fn local_name(raw: &str) -> Result<String, &'static str> {
    let valid = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':');
    if raw.is_empty() || !raw.chars().all(valid) {
        return Err("bad element name");
    }
    let local = raw.rsplit(':').next().unwrap_or(raw);
    if !local.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return Err("bad element name");
    }
    Ok(local.to_owned())
}

/// Decode character data into `out`, refusing unknown entities.
fn decode_text(raw: &str, out: &mut String) -> Result<(), &'static str> {
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let end = after.find(';').ok_or("unterminated entity")?;
        if end > 10 {
            return Err("unknown entity");
        }
        let entity = &after[..end];
        let decoded = match entity {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let number = if let Some(hex) = entity.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()
                } else if let Some(decimal) = entity.strip_prefix('#') {
                    decimal.parse().ok()
                } else {
                    None
                };
                number
                    .filter(|&n| n != 0)
                    .and_then(char::from_u32)
                    .ok_or("unknown entity")?
            }
        };
        out.push(decoded);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    if out.len() > MAX_TEXT {
        return Err("text too long");
    }
    Ok(())
}

/// Check attribute syntax: `name="value"` or `name='value'` pairs.
fn check_attributes(raw: &str) -> Result<(), &'static str> {
    let bytes = raw.as_bytes();
    let mut at = 0;
    loop {
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        if at == bytes.len() {
            return Ok(());
        }
        let start = at;
        while at < bytes.len() && bytes[at] != b'=' && !bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        local_name(&raw[start..at]).map_err(|_| "bad attribute")?;
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        if bytes.get(at) != Some(&b'=') {
            return Err("bad attribute");
        }
        at += 1;
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        let quote = *bytes.get(at).ok_or("bad attribute")?;
        if quote != b'"' && quote != b'\'' {
            return Err("bad attribute");
        }
        let close = find(bytes, at + 1, &[quote]).ok_or("bad attribute")?;
        if raw[at + 1..close].contains('<') {
            return Err("bad attribute");
        }
        at = close + 1;
    }
}

/// End of a start tag, skipping `>` inside quoted attribute values.
fn tag_end(bytes: &[u8], from: usize) -> Option<usize> {
    let mut quote = None;
    for (offset, &byte) in bytes.get(from..)?.iter().enumerate() {
        match (quote, byte) {
            (None, b'"' | b'\'') => quote = Some(byte),
            (Some(q), _) if byte == q => quote = None,
            (None, b'>') => return Some(from + offset),
            _ => {}
        }
    }
    None
}

/// Parse a whole document. The caller bounds its size before calling.
pub fn parse(input: &str) -> Result<Element, &'static str> {
    let bytes = input.as_bytes();
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut count = 0usize;
    let mut at = 0usize;
    // Skip a byte order mark.
    if input.starts_with('\u{feff}') {
        at = 3;
    }
    while at < bytes.len() {
        let next = find(bytes, at, b"<").unwrap_or(bytes.len());
        let text = &input[at..next];
        match stack.last_mut() {
            Some(open) => decode_text(text, &mut open.text)?,
            None if text.trim().is_empty() => {}
            None => return Err("text outside the root element"),
        }
        if next == bytes.len() {
            break;
        }
        at = next;
        let rest = &bytes[at..];
        if rest.starts_with(b"<?") {
            at = find(bytes, at, b"?>").ok_or("unterminated declaration")? + 2;
        } else if rest.starts_with(b"<!--") {
            at = find(bytes, at + 4, b"-->").ok_or("unterminated comment")? + 3;
        } else if rest.starts_with(b"<![CDATA[") {
            let end = find(bytes, at + 9, b"]]>").ok_or("unterminated CDATA")?;
            let open = stack.last_mut().ok_or("CDATA outside the root element")?;
            open.text.push_str(&input[at + 9..end]);
            if open.text.len() > MAX_TEXT {
                return Err("text too long");
            }
            at = end + 3;
        } else if rest.starts_with(b"<!") {
            return Err("document type declarations are refused");
        } else if rest.starts_with(b"</") {
            let end = find(bytes, at, b">").ok_or("unterminated tag")?;
            let name = local_name(input[at + 2..end].trim_end())?;
            let element = stack.pop().ok_or("unbalanced end tag")?;
            if element.name != name {
                return Err("mismatched end tag");
            }
            match stack.last_mut() {
                Some(parent) => parent.children.push(element),
                None => root = Some(element),
            }
            at = end + 1;
        } else {
            let end = tag_end(bytes, at + 1).ok_or("unterminated tag")?;
            let mut inner = &input[at + 1..end];
            let empty = inner.ends_with('/');
            if empty {
                inner = &inner[..inner.len() - 1];
            }
            let split = inner
                .find(|c: char| c.is_ascii_whitespace())
                .unwrap_or(inner.len());
            let name = local_name(&inner[..split])?;
            check_attributes(&inner[split..])?;
            if root.is_some() {
                return Err("more than one root element");
            }
            count += 1;
            if count > MAX_ELEMENTS {
                return Err("too many elements");
            }
            if stack.len() >= MAX_DEPTH {
                return Err("nested too deeply");
            }
            let element = Element {
                name,
                ..Element::default()
            };
            if empty {
                match stack.last_mut() {
                    Some(parent) => parent.children.push(element),
                    None => root = Some(element),
                }
            } else {
                stack.push(element);
            }
            at = end + 1;
        }
    }
    if !stack.is_empty() {
        return Err("unclosed element");
    }
    root.ok_or("no root element")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_names_text_and_entities() {
        let doc = parse(
            "<?xml version=\"1.0\"?>\n<!-- c --><s:Envelope xmlns:s='x'><s:Body>\
             <u:R a=\"1 > 0\"><V>a &amp; b &#x41;&#66;</V><E/><C><![CDATA[<raw>]]></C></u:R>\
             </s:Body></s:Envelope>",
        )
        .unwrap();
        assert_eq!(doc.name, "Envelope");
        let response = &doc.descendants("R")[0];
        assert_eq!(response.child_text("V"), Some("a & b AB"));
        assert_eq!(response.child_text("E"), Some(""));
        assert_eq!(response.child_text("C"), Some("<raw>"));
    }

    #[test]
    fn refuses_hostile_and_broken_documents() {
        let cases = [
            (
                "<!DOCTYPE x [<!ENTITY a 'b'>]><x>&a;</x>",
                "document type declarations are refused",
            ),
            ("<x>&a;</x>", "unknown entity"),
            ("<x>&#0;</x>", "unknown entity"),
            ("<x>&amp</x>", "unterminated entity"),
            ("<x><y></x>", "mismatched end tag"),
            ("<x>", "unclosed element"),
            ("</x>", "unbalanced end tag"),
            ("<x/><y/>", "more than one root element"),
            ("text<x/>", "text outside the root element"),
            ("", "no root element"),
            ("<x a=1/>", "bad attribute"),
            ("<x a='1/>", "unterminated tag"),
            ("<1 x='y'>", "bad element name"),
            ("<x\u{e9}/>", "bad element name"),
            ("<x><!-- </x>", "unterminated comment"),
        ];
        for (input, reason) in cases {
            assert_eq!(parse(input), Err(reason), "{input}");
        }
    }

    #[test]
    fn enforces_depth_count_and_text_limits() {
        let deep = "<a>".repeat(MAX_DEPTH + 1) + &"</a>".repeat(MAX_DEPTH + 1);
        assert_eq!(parse(&deep), Err("nested too deeply"));
        let wide = format!("<r>{}</r>", "<a/>".repeat(MAX_ELEMENTS));
        assert_eq!(parse(&wide), Err("too many elements"));
        let long = format!("<r>{}</r>", "x".repeat(MAX_TEXT + 1));
        assert_eq!(parse(&long), Err("text too long"));
        let amplified = format!("<r>{}</r>", "&amp;".repeat(MAX_TEXT + 1));
        assert_eq!(parse(&amplified), Err("text too long"));
    }

    #[test]
    fn finds_nested_descendants_in_order() {
        let doc = parse("<r><a><b>1</b></a><b>2</b><c><d><b>3</b></d></c></r>").unwrap();
        let texts: Vec<_> = doc
            .descendants("b")
            .iter()
            .map(|b| b.text.as_str())
            .collect();
        assert_eq!(texts, ["1", "2", "3"]);
    }
}
