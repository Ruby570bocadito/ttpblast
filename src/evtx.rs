//! Windows event log files (.evtx), read directly and with no dependency:
//! the file and chunk headers, the event records and the binary XML inside
//! them, with its templates and substitutions. Each record becomes a flat
//! map of fields, as an exported event would have (`EventID`, `Channel`,
//! `Hostname`, `@timestamp` and every `EventData` value by name), so Sysmon
//! and Windows' own events go through the same translation as NDJSON.
//!
//! An .evtx can come from a compromised machine: every read is bounds
//! checked, nesting is limited and a damaged record is skipped and counted,
//! never a panic. The layout follows Joachim Metz's libevtx documentation.

use std::collections::HashMap;
use std::rc::Rc;

use crate::time;

const FILE_MAGIC: &[u8] = b"ElfFile\0";
const CHUNK_MAGIC: &[u8] = b"ElfChnk\0";
const RECORD_MAGIC: &[u8] = &[0x2a, 0x2a, 0, 0];
const FILE_HEADER_SIZE: usize = 4096;
const CHUNK_SIZE: usize = 65_536;
const CHUNK_HEADER_SIZE: usize = 512;
/// Deep enough for any real event, shallow enough for a crafted one.
const MAX_DEPTH: usize = 40;
/// More substitutions than any template has.
const MAX_VALUES: usize = 4096;
/// Seconds between 1601-01-01 (FILETIME) and 1970-01-01 (Unix).
const FILETIME_EPOCH: i64 = 11_644_473_600;

type Result<T> = std::result::Result<T, &'static str>;

pub fn is_evtx(bytes: &[u8]) -> bool {
    bytes.starts_with(FILE_MAGIC)
}

/// The records of an .evtx file as flat field maps (values lowercased), and
/// how many records could not be read.
pub fn records(bytes: &[u8]) -> (Vec<HashMap<String, String>>, usize) {
    let mut out = Vec::new();
    let mut failed = 0;
    // Chunks follow the file header back to back. A file that was not
    // closed cleanly can have more of them than its header says, so every
    // block with a chunk signature is read.
    let mut offset = FILE_HEADER_SIZE;
    while offset + CHUNK_SIZE <= bytes.len() {
        let data = &bytes[offset..offset + CHUNK_SIZE];
        if data.starts_with(CHUNK_MAGIC) {
            Chunk::new(data).read(&mut out, &mut failed);
        }
        offset += CHUNK_SIZE;
    }
    (out, failed)
}

/// Bounds-checked little-endian reads inside `data[..end]`.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], pos: usize, end: usize) -> Self {
        Reader {
            data,
            pos,
            end: end.min(data.len()),
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or("tamaño imposible")?;
        if end > self.end {
            return Err("lectura fuera del registro");
        }
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn peek(&self) -> Result<u8> {
        if self.pos < self.end {
            Ok(self.data[self.pos])
        } else {
            Err("el registro se acaba antes de tiempo")
        }
    }
}

/// An element of the binary XML, before or after its substitutions are filled.
#[derive(Clone, Default)]
struct Node {
    name: String,
    attrs: Vec<(String, Vec<Piece>)>,
    children: Vec<Content>,
}

#[derive(Clone)]
enum Content {
    Node(Node),
    Piece(Piece),
}

#[derive(Clone)]
enum Piece {
    Text(String),
    /// A template's placeholder for the instance's value number `n`.
    Sub(u16),
}

/// A substitution value: text, or binary XML of its own (as `UserData` often is).
enum Value {
    Null,
    Text(String),
    Xml(Vec<Node>),
}

impl Node {
    fn elements(&self) -> impl Iterator<Item = &Node> {
        self.children.iter().filter_map(|c| match c {
            Content::Node(n) => Some(n),
            Content::Piece(_) => None,
        })
    }

    fn text(&self) -> String {
        self.children
            .iter()
            .filter_map(|c| match c {
                Content::Piece(Piece::Text(t)) => Some(t.as_str()),
                _ => None,
            })
            .collect()
    }

    fn attr(&self, name: &str) -> Option<String> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, pieces)| plain(pieces))
    }
}

/// Text of pieces that no longer have placeholders.
fn plain(pieces: &[Piece]) -> String {
    pieces
        .iter()
        .filter_map(|p| match p {
            Piece::Text(t) => Some(t.as_str()),
            Piece::Sub(_) => None,
        })
        .collect()
}

/// One 64 KiB chunk: names and templates are stored once per chunk and
/// referred to by their offset in it.
struct Chunk<'a> {
    data: &'a [u8],
    templates: HashMap<usize, Rc<[Node]>>,
}

impl<'a> Chunk<'a> {
    fn new(data: &'a [u8]) -> Self {
        Chunk {
            data,
            templates: HashMap::new(),
        }
    }

    fn read(&mut self, out: &mut Vec<HashMap<String, String>>, failed: &mut usize) {
        // Records end where the chunk's free space starts.
        let free = Reader::new(self.data, 48, 52)
            .u32()
            .map_or(CHUNK_SIZE, |f| (f as usize).min(CHUNK_SIZE));
        let mut pos = CHUNK_HEADER_SIZE;
        while pos + 28 <= free {
            if &self.data[pos..pos + 4] != RECORD_MAGIC {
                break;
            }
            let size = Reader::new(self.data, pos + 4, pos + 8)
                .u32()
                .map_or(0, |s| s as usize);
            if size < 28 || pos + size > CHUNK_SIZE {
                *failed += 1;
                break;
            }
            match self.record(pos + 24, pos + size - 4) {
                Ok(nodes) => out.push(flatten(&nodes)),
                Err(_) => *failed += 1,
            }
            pos += size;
        }
    }

    fn record(&mut self, start: usize, end: usize) -> Result<Vec<Node>> {
        let mut r = Reader::new(self.data, start, end);
        self.fragment(&mut r, false, 0)
    }

    /// A fragment: an optional header, then elements or template instances
    /// up to the end-of-stream token. `in_value` is binary XML inside a
    /// substitution value, whose elements have no dependency identifier.
    fn fragment(&mut self, r: &mut Reader<'a>, in_value: bool, depth: usize) -> Result<Vec<Node>> {
        if depth > MAX_DEPTH {
            return Err("anidamiento excesivo");
        }
        let mut nodes = Vec::new();
        while r.pos < r.end {
            match r.peek()? {
                0x00 => {
                    r.pos += 1;
                    break;
                }
                0x0f => {
                    r.take(4)?;
                }
                0x0c => nodes.extend(self.template_instance(r, depth)?),
                0x01 | 0x41 => nodes.push(self.element(r, in_value, depth + 1)?),
                _ => return Err("token inesperado en el fragmento"),
            }
        }
        Ok(nodes)
    }

    fn element(&mut self, r: &mut Reader<'a>, in_value: bool, depth: usize) -> Result<Node> {
        if depth > MAX_DEPTH {
            return Err("anidamiento excesivo");
        }
        let token = r.u8()?;
        if !in_value {
            r.u16()?; // dependency identifier
        }
        r.u32()?; // size of the element's data
        let mut node = Node {
            name: self.name_ref(r)?,
            ..Node::default()
        };
        if token & 0x40 != 0 {
            r.u32()?; // size of the attribute list
        }
        while matches!(r.peek()?, 0x06 | 0x46) {
            r.u8()?;
            let name = self.name_ref(r)?;
            let value = self.piece(r)?;
            node.attrs.push((name, vec![value]));
        }
        match r.u8()? {
            0x03 => return Ok(node), // close empty element
            0x02 => {}               // close start element
            _ => return Err("etiqueta sin cerrar"),
        }
        loop {
            match r.peek()? {
                0x04 => {
                    r.u8()?;
                    return Ok(node);
                }
                0x01 | 0x41 => {
                    let child = self.element(r, in_value, depth + 1)?;
                    node.children.push(Content::Node(child));
                }
                0x05 | 0x45 | 0x07 | 0x47 | 0x08 | 0x48 | 0x09 | 0x49 | 0x0d | 0x0e => {
                    let piece = self.piece(r)?;
                    node.children.push(Content::Piece(piece));
                }
                0x0a => {
                    // Processing instruction target, then its data.
                    r.u8()?;
                    self.name_ref(r)?;
                }
                0x0b => {
                    r.u8()?;
                    let n = r.u16()? as usize;
                    r.take(n * 2)?;
                }
                _ => return Err("token inesperado en un elemento"),
            }
        }
    }

    /// One value token: text, a placeholder, CDATA, or a character or
    /// entity reference.
    fn piece(&mut self, r: &mut Reader<'a>) -> Result<Piece> {
        match r.u8()? {
            0x05 | 0x45 => {
                let kind = r.u8()?;
                let text = match kind {
                    0x01 => {
                        let n = r.u16()? as usize;
                        utf16(r.take(n * 2)?)
                    }
                    _ => decode(
                        kind,
                        r.take(fixed_size(kind).ok_or("valor de tamaño desconocido")?)?,
                    ),
                };
                Ok(Piece::Text(text))
            }
            0x0d | 0x0e => {
                let index = r.u16()?;
                r.u8()?; // value type, given again by the instance
                Ok(Piece::Sub(index))
            }
            0x07 | 0x47 => {
                let n = r.u16()? as usize;
                Ok(Piece::Text(utf16(r.take(n * 2)?)))
            }
            0x08 | 0x48 => {
                let code = r.u16()?;
                Ok(Piece::Text(
                    char::from_u32(u32::from(code))
                        .map(String::from)
                        .unwrap_or_default(),
                ))
            }
            0x09 | 0x49 => {
                let entity = match self.name_ref(r)?.as_str() {
                    "amp" => "&",
                    "lt" => "<",
                    "gt" => ">",
                    "quot" => "\"",
                    "apos" => "'",
                    _ => "",
                };
                Ok(Piece::Text(entity.to_string()))
            }
            _ => Err("se esperaba un valor"),
        }
    }

    /// A name, by its offset in the chunk; when it is defined right here,
    /// the reader skips over it.
    fn name_ref(&mut self, r: &mut Reader<'a>) -> Result<String> {
        let offset = r.u32()? as usize;
        let (name, size) = self.name_at(offset)?;
        if offset == r.pos {
            r.take(size)?;
        }
        Ok(name)
    }

    /// [next name offset u32][hash u16][characters u16][UTF-16…][NUL u16]
    fn name_at(&self, offset: usize) -> Result<(String, usize)> {
        let mut r = Reader::new(self.data, offset, self.data.len());
        r.take(6)?;
        let n = r.u16()? as usize;
        let name = utf16(r.take(n * 2)?);
        r.take(2)?;
        Ok((name, 10 + n * 2))
    }

    fn template_instance(&mut self, r: &mut Reader<'a>, depth: usize) -> Result<Vec<Node>> {
        r.u8()?; // token
        r.u8()?; // unknown
        r.u32()?; // template identifier
        let definition = r.u32()? as usize;
        if definition == r.pos {
            // Defined inline, the first time the chunk uses it: skip it here
            // (next template offset, GUID, data size, data).
            r.take(20)?;
            let size = r.u32()? as usize;
            r.take(size)?;
        }
        let template = self.template(definition, depth)?;
        let count = r.u32()? as usize;
        if count > MAX_VALUES {
            return Err("demasiadas sustituciones");
        }
        let mut descriptors = Vec::with_capacity(count);
        for _ in 0..count {
            let size = r.u16()? as usize;
            let kind = r.u8()?;
            r.u8()?;
            descriptors.push((size, kind));
        }
        let mut values = Vec::with_capacity(count);
        for (size, kind) in descriptors {
            let start = r.pos;
            let bytes = r.take(size)?;
            values.push(match kind {
                0x00 => Value::Null,
                0x21 => {
                    let mut inner = Reader::new(self.data, start, start + size);
                    // A damaged inner fragment only loses that value.
                    self.fragment(&mut inner, true, depth + 1)
                        .map_or(Value::Null, Value::Xml)
                }
                _ => Value::Text(decode(kind, bytes)),
            });
        }
        Ok(template.iter().map(|n| fill(n, &values)).collect())
    }

    /// The template defined at `offset` (next offset, GUID, size, fragment),
    /// parsed once per chunk.
    fn template(&mut self, offset: usize, depth: usize) -> Result<Rc<[Node]>> {
        if let Some(template) = self.templates.get(&offset) {
            return Ok(template.clone());
        }
        let mut r = Reader::new(self.data, offset, self.data.len());
        r.take(20)?;
        let size = r.u32()? as usize;
        r.end = r.pos.saturating_add(size).min(self.data.len());
        let nodes: Rc<[Node]> = self.fragment(&mut r, false, depth + 1)?.into();
        self.templates.insert(offset, nodes.clone());
        Ok(nodes)
    }
}

/// A template element with its placeholders replaced by the instance's values.
fn fill(node: &Node, values: &[Value]) -> Node {
    let text = |pieces: &[Piece]| -> String {
        pieces
            .iter()
            .map(|p| match p {
                Piece::Text(t) => t.clone(),
                Piece::Sub(i) => match values.get(usize::from(*i)) {
                    Some(Value::Text(t)) => t.clone(),
                    _ => String::new(),
                },
            })
            .collect()
    };
    let mut children = Vec::with_capacity(node.children.len());
    for child in &node.children {
        match child {
            Content::Node(n) => children.push(Content::Node(fill(n, values))),
            Content::Piece(Piece::Sub(i)) => match values.get(usize::from(*i)) {
                Some(Value::Text(t)) => children.push(Content::Piece(Piece::Text(t.clone()))),
                Some(Value::Xml(nodes)) => {
                    children.extend(nodes.iter().cloned().map(Content::Node))
                }
                _ => {}
            },
            Content::Piece(p) => children.push(Content::Piece(p.clone())),
        }
    }
    Node {
        name: node.name.clone(),
        attrs: node
            .attrs
            .iter()
            .map(|(k, pieces)| (k.clone(), vec![Piece::Text(text(pieces))]))
            .collect(),
        children,
    }
}

/// The event as flat fields: the core of `System` by name (`EventID`,
/// `Channel`, `EventRecordID`; `Provider` as `SourceName`, `Computer` as
/// `Hostname`, `TimeCreated` as `@timestamp`) and the rest of it as
/// `System.*`, then each `EventData` value by its `Name` and each
/// `UserData` leaf by its element name. Values are lowercased, as for
/// NDJSON, and whitespace-only ones are left out, as parsing the event's XML
/// (and so the Sysmon exporter) does.
fn flatten(nodes: &[Node]) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let Some(event) = nodes.iter().find(|n| n.name == "Event") else {
        return fields;
    };
    let mut put = |key: String, value: String| {
        if !value.trim().is_empty() {
            fields.entry(key).or_insert_with(|| value.to_lowercase());
        }
    };
    for section in event.elements() {
        match section.name.as_str() {
            "System" => {
                for item in section.elements() {
                    match item.name.as_str() {
                        "Provider" => {
                            put("SourceName".into(), item.attr("Name").unwrap_or_default())
                        }
                        "TimeCreated" => put(
                            "@timestamp".into(),
                            item.attr("SystemTime").unwrap_or_default(),
                        ),
                        "Computer" => put("Hostname".into(), item.text()),
                        name @ ("EventID" | "Channel" | "EventRecordID") => {
                            put(name.to_string(), item.text())
                        }
                        name => {
                            put(format!("System.{name}"), item.text());
                            for (attr, pieces) in &item.attrs {
                                put(format!("System.{name}.{attr}"), plain(pieces));
                            }
                        }
                    }
                }
            }
            "EventData" => {
                let mut unnamed = 0;
                for data in section.elements() {
                    let key = data.attr("Name").unwrap_or_else(|| {
                        unnamed += 1;
                        format!("{}{unnamed}", data.name)
                    });
                    put(key, data.text());
                }
            }
            "UserData" => {
                let mut stack: Vec<&Node> = section.elements().collect();
                while let Some(node) = stack.pop() {
                    if node.elements().next().is_none() {
                        put(node.name.clone(), node.text());
                    } else {
                        stack.extend(node.elements());
                    }
                }
            }
            _ => {}
        }
    }
    fields
}

/// Size of the fixed-size value types, for values written inline.
fn fixed_size(kind: u8) -> Option<usize> {
    match kind {
        0x03 | 0x04 => Some(1),
        0x05 | 0x06 => Some(2),
        0x07 | 0x08 | 0x0b | 0x0d | 0x14 => Some(4),
        0x09 | 0x0a | 0x0c | 0x11 | 0x15 => Some(8),
        0x0f | 0x12 => Some(16),
        _ => None,
    }
}

/// A value as Windows would render it in the event's XML.
fn decode(kind: u8, b: &[u8]) -> String {
    let int = |n: usize| -> Option<u64> {
        (b.len() >= n).then(|| {
            let mut v = [0u8; 8];
            v[..n].copy_from_slice(&b[..n]);
            u64::from_le_bytes(v)
        })
    };
    let text = match kind {
        0x01 => Some(utf16(b)),
        0x02 => Some(
            String::from_utf8_lossy(b)
                .trim_end_matches('\0')
                .to_string(),
        ),
        0x03 => int(1).map(|v| (v as u8 as i8).to_string()),
        0x04 => int(1).map(|v| v.to_string()),
        0x05 => int(2).map(|v| (v as u16 as i16).to_string()),
        0x06 => int(2).map(|v| v.to_string()),
        0x07 => int(4).map(|v| (v as u32 as i32).to_string()),
        0x08 => int(4).map(|v| v.to_string()),
        0x09 => int(8).map(|v| (v as i64).to_string()),
        0x0a => int(8).map(|v| v.to_string()),
        0x0b => int(4).map(|v| f32::from_bits(v as u32).to_string()),
        0x0c => int(8).map(|v| f64::from_bits(v).to_string()),
        0x0d => int(4).map(|v| (v != 0).to_string()),
        0x0f => guid(b),
        0x10 => int(b.len().min(8)).map(|v| format!("0x{v:016x}")),
        0x11 => int(8).and_then(filetime),
        0x12 => systemtime(b),
        0x13 => sid(b),
        0x14 => int(4).map(|v| format!("0x{v:x}")),
        0x15 => int(8).map(|v| format!("0x{v:x}")),
        k if k & 0x80 != 0 => Some(array(k & 0x7f, b)),
        _ => None,
    };
    text.unwrap_or_else(|| hex(b))
}

/// Arrays: strings separated by NULs, or values of a fixed size.
fn array(kind: u8, b: &[u8]) -> String {
    if kind == 0x01 {
        let units: Vec<u16> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        return units
            .split(|&u| u == 0)
            .filter(|s| !s.is_empty())
            .map(String::from_utf16_lossy)
            .collect::<Vec<_>>()
            .join(",");
    }
    match fixed_size(kind) {
        Some(size) => b
            .chunks_exact(size)
            .map(|item| decode(kind, item))
            .collect::<Vec<_>>()
            .join(","),
        None => hex(b),
    }
}

fn utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn guid(b: &[u8]) -> Option<String> {
    if b.len() < 16 {
        return None;
    }
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    Some(format!(
        "{{{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

/// 100-nanosecond intervals since 1601, as RFC 3339 with seven decimals.
fn filetime(ticks: u64) -> Option<String> {
    let seconds = i64::try_from(ticks / 10_000_000).ok()? - FILETIME_EPOCH;
    let fraction = ticks % 10_000_000;
    let base = time::format_rfc3339(seconds);
    Some(format!("{}.{fraction:07}Z", base.trim_end_matches('Z')))
}

fn systemtime(b: &[u8]) -> Option<String> {
    if b.len() < 16 {
        return None;
    }
    let f = |i: usize| u16::from_le_bytes([b[2 * i], b[2 * i + 1]]);
    // year, month, day of week, day, hour, minute, second, milliseconds
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        f(0),
        f(1),
        f(3),
        f(4),
        f(5),
        f(6),
        f(7)
    ))
}

/// S-revision-authority-subauthorities…
fn sid(b: &[u8]) -> Option<String> {
    if b.len() < 8 {
        return None;
    }
    let count = usize::from(b[1]);
    if b.len() < 8 + 4 * count {
        return None;
    }
    let authority = b[2..8].iter().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    let mut text = format!("S-{}-{authority}", b[0]);
    for i in 0..count {
        let at = 8 + 4 * i;
        let sub = u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        text.push_str(&format!("-{sub}"));
    }
    Some(text)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::rng::Rng;

    /// Writes a minimal but well-formed .evtx: the binary XML of each
    /// record is a template instance, and the first record of the chunk
    /// carries the template definition inline, as Windows writes it.
    pub(crate) struct Writer {
        chunk: Vec<u8>,
        records: u64,
        template: Option<u32>,
    }

    /// (EventID, Computer, channel, provider, FILETIME, EventData).
    pub(crate) type Sample<'a> = (
        u16,
        &'a str,
        &'a str,
        &'a str,
        u64,
        &'a [(&'a str, &'a str)],
    );

    impl Writer {
        pub(crate) fn new() -> Self {
            let mut chunk = vec![0u8; CHUNK_SIZE];
            chunk[..8].copy_from_slice(CHUNK_MAGIC);
            Writer {
                chunk,
                records: 0,
                template: None,
            }
        }

        fn utf16(text: &str) -> Vec<u8> {
            text.encode_utf16().flat_map(u16::to_le_bytes).collect()
        }

        /// A name defined inline at the current position of `out`, which
        /// starts at chunk offset `base`.
        fn name(out: &mut Vec<u8>, base: usize, name: &str) {
            let here = (base + out.len() + 4) as u32;
            out.extend(here.to_le_bytes());
            out.extend(0u32.to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend((name.encode_utf16().count() as u16).to_le_bytes());
            out.extend(Self::utf16(name));
            out.extend(0u16.to_le_bytes());
        }

        fn open(out: &mut Vec<u8>, base: usize, name: &str, attributes: bool) {
            out.push(if attributes { 0x41 } else { 0x01 });
            out.extend(0xffffu16.to_le_bytes());
            out.extend(0u32.to_le_bytes());
            Self::name(out, base, name);
            if attributes {
                out.extend(0u32.to_le_bytes());
            }
        }

        fn attribute_text(out: &mut Vec<u8>, base: usize, name: &str, value: &str) {
            out.push(0x06);
            Self::name(out, base, name);
            out.push(0x05);
            out.push(0x01);
            out.extend((value.encode_utf16().count() as u16).to_le_bytes());
            out.extend(Self::utf16(value));
        }

        fn attribute_sub(out: &mut Vec<u8>, base: usize, name: &str, index: u16, kind: u8) {
            out.push(0x06);
            Self::name(out, base, name);
            out.push(0x0d);
            out.extend(index.to_le_bytes());
            out.push(kind);
        }

        fn sub(out: &mut Vec<u8>, index: u16, kind: u8) {
            out.push(0x0e);
            out.extend(index.to_le_bytes());
            out.push(kind);
        }

        /// <Event><System><Provider Name=%3/><EventID>%0</EventID>
        /// <TimeCreated SystemTime=%1/><Channel>%4</Channel>
        /// <Computer>%2</Computer></System><EventData>
        /// <Data Name="…">%5…</Data>…</EventData></Event>
        fn template(base: usize, data_names: &[&str]) -> Vec<u8> {
            let mut t = vec![0x0f, 0x01, 0x01, 0x00];
            Self::open(&mut t, base, "Event", false);
            t.push(0x02);
            Self::open(&mut t, base, "System", false);
            t.push(0x02);
            Self::open(&mut t, base, "Provider", true);
            Self::attribute_sub(&mut t, base, "Name", 3, 0x01);
            t.push(0x03);
            Self::open(&mut t, base, "EventID", false);
            t.push(0x02);
            Self::sub(&mut t, 0, 0x06);
            t.push(0x04);
            Self::open(&mut t, base, "TimeCreated", true);
            Self::attribute_sub(&mut t, base, "SystemTime", 1, 0x11);
            t.push(0x03);
            Self::open(&mut t, base, "Channel", false);
            t.push(0x02);
            Self::sub(&mut t, 4, 0x01);
            t.push(0x04);
            Self::open(&mut t, base, "Computer", false);
            t.push(0x02);
            Self::sub(&mut t, 2, 0x01);
            t.push(0x04);
            t.push(0x04); // </System>
            Self::open(&mut t, base, "EventData", false);
            t.push(0x02);
            for (i, name) in data_names.iter().enumerate() {
                Self::open(&mut t, base, "Data", true);
                Self::attribute_text(&mut t, base, "Name", name);
                t.push(0x02);
                Self::sub(&mut t, 5 + i as u16, 0x01);
                t.push(0x04);
            }
            t.push(0x04); // </EventData>
            t.push(0x04); // </Event>
            t.push(0x00);
            t
        }

        pub(crate) fn record(&mut self, sample: Sample) {
            let (event_id, computer, channel, provider, filetime, data) = sample;
            let start = CHUNK_HEADER_SIZE + self.used();
            let names: Vec<&str> = data.iter().map(|(k, _)| *k).collect();
            let mut body = vec![0x0f, 0x01, 0x01, 0x00, 0x0c, 0x01];
            body.extend(1u32.to_le_bytes());
            let xml_start = start + 24;
            match self.template {
                Some(offset) => body.extend(offset.to_le_bytes()),
                None => {
                    let definition = (xml_start + body.len() + 4) as u32;
                    body.extend(definition.to_le_bytes());
                    let fragment = Self::template(definition as usize + 24, &names);
                    body.extend(0u32.to_le_bytes());
                    body.extend([0u8; 16]);
                    body.extend((fragment.len() as u32).to_le_bytes());
                    body.extend(fragment);
                    self.template = Some(definition);
                }
            }
            let mut values: Vec<(u8, Vec<u8>)> = vec![
                (0x06, event_id.to_le_bytes().to_vec()),
                (0x11, filetime.to_le_bytes().to_vec()),
                (0x01, Self::utf16(computer)),
                (0x01, Self::utf16(provider)),
                (0x01, Self::utf16(channel)),
            ];
            values.extend(data.iter().map(|(_, v)| (0x01, Self::utf16(v))));
            body.extend((values.len() as u32).to_le_bytes());
            for (kind, bytes) in &values {
                body.extend((bytes.len() as u16).to_le_bytes());
                body.push(*kind);
                body.push(0);
            }
            for (_, bytes) in &values {
                body.extend(bytes);
            }
            body.push(0x00);
            let size = (24 + body.len() + 4) as u32;
            self.records += 1;
            let mut record = RECORD_MAGIC.to_vec();
            record.extend(size.to_le_bytes());
            record.extend(self.records.to_le_bytes());
            record.extend(filetime.to_le_bytes());
            record.extend(body);
            record.extend(size.to_le_bytes());
            self.chunk[start..start + record.len()].copy_from_slice(&record);
            let free = (start + record.len()) as u32;
            self.chunk[48..52].copy_from_slice(&free.to_le_bytes());
        }

        fn used(&self) -> usize {
            let free = u32::from_le_bytes([
                self.chunk[48],
                self.chunk[49],
                self.chunk[50],
                self.chunk[51],
            ]) as usize;
            free.saturating_sub(CHUNK_HEADER_SIZE)
        }

        pub(crate) fn file(&self) -> Vec<u8> {
            let mut file = vec![0u8; FILE_HEADER_SIZE];
            file[..8].copy_from_slice(FILE_MAGIC);
            file.extend(&self.chunk);
            file
        }
    }

    /// 2026-10-30T18:53:44.1234567Z as a FILETIME.
    pub(crate) const WHEN: u64 = (1_793_386_424 + FILETIME_EPOCH as u64) * 10_000_000 + 1_234_567;

    fn sysmon_file() -> Vec<u8> {
        let mut w = Writer::new();
        let data = [
            ("Image", r"C:\Windows\System32\whoami.exe"),
            ("ParentImage", r"C:\Windows\System32\cmd.exe"),
        ];
        w.record((
            1,
            "PC-RAFA",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Sysmon",
            WHEN,
            &data,
        ));
        let data = [
            ("Image", r"C:\Windows\System32\systeminfo.exe"),
            ("ParentImage", r"C:\Windows\System32\cmd.exe"),
        ];
        w.record((
            1,
            "PC-RAFA",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Sysmon",
            WHEN + 600_000_000,
            &data,
        ));
        w.file()
    }

    #[test]
    fn reads_records_through_their_template() {
        let file = sysmon_file();
        assert!(is_evtx(&file));
        let (records, failed) = records(&file);
        assert_eq!(failed, 0);
        assert_eq!(records.len(), 2);
        let first = &records[0];
        assert_eq!(first["EventID"], "1");
        assert_eq!(first["Hostname"], "pc-rafa");
        assert_eq!(first["Channel"], "microsoft-windows-sysmon/operational");
        assert_eq!(first["SourceName"], "microsoft-windows-sysmon");
        assert_eq!(first["Image"], r"c:\windows\system32\whoami.exe");
        assert_eq!(first["@timestamp"], "2026-10-30t18:53:44.1234567z");
        // The second record reuses the template defined in the first one.
        assert_eq!(records[1]["Image"], r"c:\windows\system32\systeminfo.exe");
        assert_eq!(records[1]["@timestamp"], "2026-10-30t18:54:44.1234567z");
    }

    #[test]
    fn folders_mix_evtx_and_ndjson_and_sysmon_records_encode() {
        let dir = std::env::temp_dir().join(format!("ttpblast-evtx-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sysmon.evtx"), sysmon_file()).unwrap();
        std::fs::write(
            dir.join("other.ndjson"),
            r#"{"@timestamp":"2026-10-30T19:00:00Z","host":{"name":"pc-rafa"},"event":{"action":"start"},"process":{"name":"schtasks.exe"}}"#,
        )
        .unwrap();
        std::fs::write(dir.join("notes.txt"), "not telemetry").unwrap();
        let loaded = crate::events::load(dir.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(loaded.events.len(), 3);
        assert_eq!(loaded.skipped, 0);
        let alphabet = crate::alphabet::Alphabet::default_set();
        let mut codes: Vec<&str> = loaded
            .events
            .iter()
            .filter_map(|e| alphabet.encode(e).map(|s| alphabet.code(s)))
            .collect();
        codes.sort_unstable();
        assert_eq!(codes, ["SID", "TSK", "USR"]);
        assert!(
            loaded
                .events
                .iter()
                .all(|e| e.host == "pc-rafa" && e.ts.is_some())
        );
    }

    #[test]
    fn damaged_files_never_panic() {
        let file = sysmon_file();
        let mut rng = Rng::new(17);
        for round in 0..400 {
            let mut copy = file.clone();
            // Flip bytes inside the records, cut the file short, or both.
            for _ in 0..1 + round % 8 {
                let at = FILE_HEADER_SIZE + rng.below(1400) as usize;
                copy[at] = rng.below(256) as u8;
            }
            if round % 5 == 0 {
                copy.truncate(FILE_HEADER_SIZE + CHUNK_SIZE - rng.below(64) as usize);
            }
            assert!(records(&copy).0.len() <= 2);
        }
        assert_eq!(records(b"ElfFile\0").0.len(), 0);
        assert_eq!(records(&[]).0.len(), 0);
    }

    /// Compares the reader with Windows' own renderer (`Get-WinEvent`) on a
    /// real file, record by record: ID, provider, computer, time and every
    /// named `EventData` value. Windows only, and the file stays on your
    /// machine: `TTPBLAST_EVTX=Application.evtx cargo test evtx -- --ignored`
    /// (export one with `wevtutil epl Application Application.evtx`).
    #[test]
    #[ignore]
    #[cfg(windows)]
    fn matches_windows_on_a_real_file() {
        let Ok(path) = std::env::var("TTPBLAST_EVTX") else {
            return;
        };
        let out = std::env::temp_dir().join(format!("ttpblast-evtx-{}.ndjson", std::process::id()));
        let script = format!(
            "Get-WinEvent -Path '{path}' -Oldest -MaxEvents 3000 | ForEach-Object {{ \
               $x = [xml]$_.ToXml(); $d = [ordered]@{{}}; \
               foreach ($e in $x.Event.EventData.Data) {{ $n = $e.GetAttribute('Name'); if ($n) {{ $d[$n] = [string]$e.InnerText }} }}; \
               [ordered]@{{ id = $_.RecordId; eid = $_.Id; provider = $_.ProviderName; computer = $_.MachineName; \
                 time = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss'); data = $d }} \
               | ConvertTo-Json -Compress -Depth 4 }} | Out-File -Encoding utf8 '{}'",
            out.display()
        );
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .status()
            .expect("PowerShell arranca");
        assert!(status.success(), "Get-WinEvent falló con {path}");
        let reference = std::fs::read_to_string(&out).expect("referencia de Windows");
        std::fs::remove_file(&out).ok();
        let (records, failed) = records(&std::fs::read(&path).expect("fichero .evtx"));
        let by_id: HashMap<&str, &HashMap<String, String>> = records
            .iter()
            .filter_map(|r| Some((r.get("EventRecordID")?.as_str(), r)))
            .collect();
        let (mut checked, mut wrong) = (0, Vec::new());
        for line in reference
            .trim_start_matches('\u{feff}')
            .lines()
            .filter(|l| !l.trim().is_empty())
        {
            let want: serde_json::Value = serde_json::from_str(line).expect("JSON de PowerShell");
            let id = want["id"].to_string();
            let Some(got) = by_id.get(id.as_str()) else {
                wrong.push(format!("{id}: no se ha leído"));
                continue;
            };
            checked += 1;
            // Parsing XML turns CR LF, and a lone CR, into LF; the record
            // keeps them as they were written.
            let mut check = |field: &str, expected: &str| {
                let have = got.get(field).map_or(String::new(), |v| {
                    v.replace("\r\n", "\n").replace('\r', "\n")
                });
                if have != expected.to_lowercase() {
                    let cut = |s: &str| s.chars().take(90).collect::<String>();
                    wrong.push(format!(
                        "{id} {field} ({} y {} caracteres): {:?} en vez de {:?}",
                        have.chars().count(),
                        expected.chars().count(),
                        cut(&have),
                        cut(&expected.to_lowercase())
                    ));
                }
            };
            check("EventID", &want["eid"].to_string());
            check("SourceName", want["provider"].as_str().unwrap_or(""));
            check("Hostname", want["computer"].as_str().unwrap_or(""));
            if let Some(data) = want["data"].as_object() {
                for (key, value) in data {
                    check(key, value.as_str().unwrap_or(""));
                }
            }
            let time = got.get("@timestamp").map_or("", |t| &t[..t.len().min(19)]);
            let expected = want["time"].as_str().unwrap_or("").to_lowercase();
            if time != expected {
                wrong.push(format!("{id} @timestamp: {time:?} en vez de {expected:?}"));
            }
        }
        println!(
            "{path}: {checked} registros comparados, {failed} sin leer, {} diferencias",
            wrong.len()
        );
        assert!(
            wrong.is_empty() && failed == 0 && checked > 0,
            "{}",
            wrong
                .iter()
                .take(30)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    #[test]
    fn values_render_as_windows_does() {
        assert_eq!(decode(0x0d, &1u32.to_le_bytes()), "true");
        assert_eq!(decode(0x0d, &0u32.to_le_bytes()), "false");
        assert_eq!(decode(0x06, &445u16.to_le_bytes()), "445");
        assert_eq!(
            decode(0x15, &0x8000_0000_0000_0000u64.to_le_bytes()),
            "0x8000000000000000"
        );
        let sid_bytes = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(decode(0x13, &sid_bytes), "S-1-5-18");
        let guid_bytes = [
            0x5f, 0x38, 0x70, 0x57, 0x2a, 0xc2, 0xe0, 0x43, 0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f,
            0xfb, 0xd9,
        ];
        assert_eq!(
            decode(0x0f, &guid_bytes),
            "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
        );
        assert_eq!(
            decode(0x11, &WHEN.to_le_bytes()),
            "2026-10-30T18:53:44.1234567Z"
        );
        let names: Vec<u8> = "a\0bc\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode(0x81, &names), "a,bc");
    }
}
