//! Baseline: record the currently known-good host state, then report only deltas.
//!
//! This is the most practical capability of a host scanner: a backdoor adds one
//! entry to an existing inventory, which is far more accurate than judging every cron line from scratch.

use crate::model::SnapshotItem;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub created_at: String,
    pub host: String,
    pub items: Vec<SnapshotItem>,
}

impl Baseline {
    pub fn new(host: String, items: Vec<SnapshotItem>) -> Self {
        Baseline {
            version: VERSION,
            created_at: crate::util::now_rfc3339(),
            host,
            items: dedupe(items),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = crate::util::read_text(path, 64 * crate::util::MB)
            .with_context(|| format!("cannot read baseline: {}", path.display()))?;
        let mut b: Baseline = serde_json::from_str(&text)
            .with_context(|| format!("invalid baseline format: {}", path.display()))?;
        if b.version != VERSION {
            anyhow::bail!(
                "incompatible baseline version: file v{}, binary v{}",
                b.version,
                VERSION
            );
        }
        b.items = dedupe(std::mem::take(&mut b.items));
        Ok(b)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(path, text)
            .with_context(|| format!("cannot write baseline: {}", path.display()))?;
        Ok(())
    }

    fn map(&self) -> BTreeMap<String, &SnapshotItem> {
        self.items.iter().map(|i| (i.key.clone(), i)).collect()
    }
}

pub struct Diff {
    pub added: Vec<SnapshotItem>,
    pub removed: Vec<SnapshotItem>,
    pub total: usize,
}

pub fn diff(old: &Baseline, new: &Baseline) -> Diff {
    let old_map = old.map();
    let new_map = new.map();
    let added = new_map
        .iter()
        .filter(|(k, _)| !old_map.contains_key(*k))
        .map(|(_, v)| (*v).clone())
        .collect();
    let removed = old_map
        .iter()
        .filter(|(k, _)| !new_map.contains_key(*k))
        .map(|(_, v)| (*v).clone())
        .collect();
    Diff {
        added,
        removed,
        total: new_map.len(),
    }
}

fn dedupe(items: Vec<SnapshotItem>) -> Vec<SnapshotItem> {
    let mut map: BTreeMap<String, SnapshotItem> = BTreeMap::new();
    for it in items {
        map.insert(it.key.clone(), it);
    }
    map.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(k: &str) -> SnapshotItem {
        SnapshotItem {
            key: k.into(),
            kind: "cron".into(),
            path: k.into(),
            detail: "x".into(),
        }
    }

    #[test]
    fn detects_added_and_removed() {
        let a = Baseline::new("h".into(), vec![item("a"), item("b")]);
        let b = Baseline::new("h".into(), vec![item("b"), item("c")]);
        let d = diff(&a, &b);
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].key, "c");
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].key, "a");
    }

    #[test]
    fn dedupes_keys() {
        let b = Baseline::new("h".into(), vec![item("a"), item("a")]);
        assert_eq!(b.items.len(), 1);
    }
}
