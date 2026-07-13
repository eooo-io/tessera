use serde_json::{Map, Value};

use super::IngestionIssue;

#[derive(Debug, Clone)]
pub(super) struct ArchiveItem {
    pub index: u64,
    pub byte_start: u64,
    pub byte_end: u64,
    pub line_start: u64,
    pub line_end: u64,
    pub value: Value,
}

pub(super) fn parse_archive_items(source: &[u8]) -> Result<Vec<ArchiveItem>, IngestionIssue> {
    std::str::from_utf8(source).map_err(|_| IngestionIssue::ParserFailure)?;
    let start = skip_ws(source, 0);
    if source.get(start) == Some(&b'[') {
        return parse_array(source, start);
    }

    let value: Value = serde_json::from_slice(source).map_err(|_| IngestionIssue::ParserFailure)?;
    let items = value
        .as_object()
        .and_then(|object| object.get("conversations"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![value]);
    Ok(items
        .into_iter()
        .enumerate()
        .map(|(index, value)| ArchiveItem {
            index: index as u64,
            byte_start: start as u64,
            byte_end: source.len() as u64,
            line_start: line_at(source, start),
            line_end: line_at(source, source.len()),
            value,
        })
        .collect())
}

fn parse_array(source: &[u8], array_start: usize) -> Result<Vec<ArchiveItem>, IngestionIssue> {
    let mut cursor = skip_ws(source, array_start + 1);
    let mut items = Vec::new();
    loop {
        match source.get(cursor) {
            Some(b']') => {
                cursor = skip_ws(source, cursor + 1);
                return (cursor == source.len())
                    .then_some(items)
                    .ok_or(IngestionIssue::ParserFailure);
            }
            None => return Err(IngestionIssue::ParserFailure),
            _ => {}
        }

        let start = cursor;
        let mut stream =
            serde_json::Deserializer::from_slice(&source[start..]).into_iter::<Value>();
        let value = stream
            .next()
            .transpose()
            .map_err(|_| IngestionIssue::ParserFailure)?
            .ok_or(IngestionIssue::ParserFailure)?;
        let end = start + stream.byte_offset();
        items.push(ArchiveItem {
            index: items.len() as u64,
            byte_start: start as u64,
            byte_end: end as u64,
            line_start: line_at(source, start),
            line_end: line_at(source, end),
            value,
        });
        cursor = skip_ws(source, end);
        match source.get(cursor) {
            Some(b',') => {
                cursor = skip_ws(source, cursor + 1);
                if source.get(cursor) == Some(&b']') {
                    return Err(IngestionIssue::ParserFailure);
                }
            }
            Some(b']') => {}
            _ => return Err(IngestionIssue::ParserFailure),
        }
    }
}

fn skip_ws(source: &[u8], mut cursor: usize) -> usize {
    while source
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    cursor
}

fn line_at(source: &[u8], offset: usize) -> u64 {
    1 + source[..offset.min(source.len())]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u64
}

pub(super) fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    format!("{prefix}_{}", &hasher.finalize().to_hex()[..32])
}

pub(super) fn string_any(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str).map(str::to_owned))
}

pub(super) fn timestamp(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => chrono::DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|_| value.clone()),
        Value::Number(value) => {
            let seconds = value
                .as_i64()
                .or_else(|| value.as_f64().map(|v| v as i64))?;
            chrono::DateTime::from_timestamp(seconds, 0)
                .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        }
        _ => None,
    }
}
