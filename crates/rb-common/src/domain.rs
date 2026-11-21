//! The domain matchers of `sing/common/domain`: a succinct trie
//! (`succinctSet`, after github.com/openacid/succinct) over reversed
//! domains, used by `Matcher` (domain and domain_suffix) and
//! `AdGuardMatcher` (AdGuard DNS filter lines). The trie is stored as is in
//! binary rule-sets, so it is built exactly as sing-box builds it.

use crate::varbin::{ReadError, Reader};

const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';
const ANY_LABEL: u8 = b'*';
const SUFFIX_LABEL: u8 = 0x08; // '\b'

/// `succinctSet`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuccinctSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    ranks: Vec<i32>,
    selects: Vec<i32>,
}

fn set_bit(bitmap: &mut Vec<u64>, index: usize, value: u64) {
    while index >> 6 >= bitmap.len() {
        bitmap.push(0);
    }
    bitmap[index >> 6] |= value << (index & 63);
}

/// `getBit`; bits past the end read as `outside`.
fn get_bit(bitmap: &[u64], index: usize, outside: bool) -> bool {
    match bitmap.get(index >> 6) {
        Some(word) => word & (1 << (index & 63)) != 0,
        None => outside,
    }
}

const fn select8_lookup() -> [u8; 256 * 8] {
    let mut table = [0u8; 256 * 8];
    let mut i = 0;
    while i < 256 {
        let mut word = i as u8;
        let mut j = 0;
        while j < 8 {
            // the j-th set bit of i, 8 when there is none
            table[i * 8 + j] = if word == 0 { 8 } else { word.trailing_zeros() as u8 };
            word &= word.wrapping_sub(1);
            j += 1;
        }
        i += 1;
    }
    table
}

static SELECT8: [u8; 256 * 8] = select8_lookup();

fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

impl SuccinctSet {
    /// `newSuccinctSet`; `keys` must be sorted and unique.
    pub fn new(keys: &[Vec<u8>]) -> Self {
        let mut set = SuccinctSet::default();
        let mut label_index = 0usize;
        // (start, end, column)
        let mut queue: Vec<(usize, usize, usize)> = vec![(0, keys.len(), 0)];
        let mut i = 0;
        while i < queue.len() {
            let (mut start, end, column) = queue[i];
            if start < end && column == keys[start].len() {
                // a leaf node
                start += 1;
                set_bit(&mut set.leaves, i, 1);
            }
            let mut j = start;
            while j < end {
                let from = j;
                while j < end && keys[j][column] == keys[from][column] {
                    j += 1;
                }
                queue.push((from, j, column + 1));
                set.labels.push(keys[from][column]);
                set_bit(&mut set.label_bitmap, label_index, 0);
                label_index += 1;
            }
            set_bit(&mut set.label_bitmap, label_index, 1);
            label_index += 1;
            i += 1;
        }
        set.init();
        set
    }

    fn init(&mut self) {
        // indexSelect32R64
        let bits = self.label_bitmap.len() << 6;
        let mut selects = Vec::new();
        let mut ith: i64 = -1;
        for i in 0..bits {
            if self.label_bitmap[i >> 6] & (1 << (i & 63)) != 0 {
                ith += 1;
                if ith & 31 == 0 {
                    selects.push(i as i32);
                }
            }
        }
        // indexRank64 with a trailing entry
        let mut ranks = Vec::with_capacity(self.label_bitmap.len() + 1);
        let mut count = 0i32;
        for word in &self.label_bitmap {
            ranks.push(count);
            count += word.count_ones() as i32;
        }
        ranks.push(count);
        self.selects = selects;
        self.ranks = ranks;
    }

    /// `countZeros`.
    fn count_zeros(&self, i: usize) -> Option<usize> {
        let word_index = i >> 6;
        let rank = *self.ranks.get(word_index)?;
        let word = *self.label_bitmap.get(word_index)?;
        let ones = rank + (word & mask((i & 63) as u32)).count_ones() as i32;
        Some(i - ones as usize)
    }

    /// `selectIthOne` (`select32R64`): the index of the `i`-th set bit.
    fn select_ith_one(&self, i: usize) -> Option<usize> {
        let i = i as i32;
        let mut word_index = (*self.selects.get((i >> 5) as usize)? >> 6) as usize;
        while *self.ranks.get(word_index + 1)? <= i {
            word_index += 1;
        }
        let word = *self.label_bitmap.get(word_index)?;
        let mut ww = word;
        let base = (word_index << 6) as i32;
        let mut find_ith = i - self.ranks[word_index];
        let mut offset = 0i32;
        let ones = (ww as u32).count_ones() as i32;
        if ones <= find_ith {
            find_ith -= ones;
            offset |= 32;
            ww >>= 32;
        }
        let ones = (ww as u16).count_ones() as i32;
        if ones <= find_ith {
            find_ith -= ones;
            offset |= 16;
            ww >>= 16;
        }
        let ones = (ww as u8).count_ones() as i32;
        let a = if ones <= find_ith {
            i32::from(SELECT8[((ww >> 5) & 0x7f8) as usize | (find_ith - ones) as usize]) + offset + 8
        } else {
            i32::from(SELECT8[((ww & 0xff) << 3) as usize | find_ith as usize]) + offset
        };
        Some((a + base) as usize)
    }

    /// The child node of the label at `bitmap_index` and the bitmap index
    /// of its first label.
    fn child(&self, bitmap_index: usize) -> Option<(usize, usize)> {
        let node = self.count_zeros(bitmap_index + 1)?;
        let first = self.select_ith_one(node.checked_sub(1)?)? + 1;
        Some((node, first))
    }

    fn label(&self, bitmap_index: usize, node: usize) -> Option<u8> {
        self.labels.get(bitmap_index.checked_sub(node)?).copied()
    }

    fn is_leaf(&self, node: usize) -> bool {
        get_bit(&self.leaves, node, false)
    }

    fn is_end(&self, bitmap_index: usize) -> bool {
        get_bit(&self.label_bitmap, bitmap_index, true)
    }

    /// `succinctSet.keys`.
    pub fn keys(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        if self.is_leaf(0) {
            result.push(Vec::new());
        }
        let mut current = Vec::new();
        // (node, bitmap index)
        let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
        let mut steps = 0usize;
        let limit = self.label_bitmap.len() * 64 * 2 + 16;
        while let Some(&(node, bitmap_index)) = stack.last() {
            steps += 1;
            if steps > limit {
                break;
            }
            if self.is_end(bitmap_index) {
                stack.pop();
                if let Some(top) = stack.last_mut() {
                    current.pop();
                    top.1 += 1;
                }
                continue;
            }
            let (Some(label), Some((next_node, next_index))) = (self.label(bitmap_index, node), self.child(bitmap_index))
            else {
                break;
            };
            current.push(label);
            if self.is_leaf(next_node) {
                result.push(current.clone());
            }
            stack.push((next_node, next_index));
        }
        result
    }

    /// `readSuccinctSet`.
    pub fn read(reader: &mut Reader) -> Result<Self, ReadError> {
        reader.read_u8()?;
        let mut leaves = reader.read_u64_slice()?;
        let label_bitmap = reader.read_u64_slice()?;
        let labels = reader.read_byte_slice()?;
        let mut ones = 0usize;
        let mut last_one: i64 = -1;
        for (word_index, word) in label_bitmap.iter().enumerate() {
            ones += word.count_ones() as usize;
            if *word != 0 {
                last_one = ((word_index << 6) | (63 - word.leading_zeros() as usize)) as i64;
            }
        }
        let zeros = last_one + 1 - ones as i64;
        if ones as i64 != zeros + 1 || labels.len() as i64 != zeros {
            return Err(ReadError::Invalid("domain: malformed succinct set".into()));
        }
        let leaves_words = (ones + 63) >> 6;
        if leaves.len() < leaves_words {
            leaves.resize(leaves_words, 0);
        }
        let mut set = SuccinctSet { leaves, label_bitmap, labels, ranks: Vec::new(), selects: Vec::new() };
        set.init();
        Ok(set)
    }

    /// `succinctSet.Write`.
    pub fn write(&self, buffer: &mut Vec<u8>) {
        buffer.push(0);
        crate::varbin::write_uvarint(buffer, self.leaves.len() as u64);
        for word in &self.leaves {
            buffer.extend_from_slice(&word.to_be_bytes());
        }
        crate::varbin::write_uvarint(buffer, self.label_bitmap.len() as u64);
        for word in &self.label_bitmap {
            buffer.extend_from_slice(&word.to_be_bytes());
        }
        crate::varbin::write_uvarint(buffer, self.labels.len() as u64);
        buffer.extend_from_slice(&self.labels);
    }
}

/// `reverseDomain`: the string reversed by UTF-8 characters (an invalid
/// byte counts as one character).
pub fn reverse_domain(domain: &[u8]) -> Vec<u8> {
    let mut units: Vec<&[u8]> = Vec::with_capacity(domain.len());
    for chunk in domain.utf8_chunks() {
        let valid = chunk.valid();
        let mut start = 0;
        for (index, character) in valid.char_indices() {
            let end = index + character.len_utf8();
            units.push(&valid.as_bytes()[start.max(index)..end]);
            start = end;
        }
        for byte in chunk.invalid().chunks(1) {
            units.push(byte);
        }
    }
    units.iter().rev().flat_map(|unit| unit.iter().copied()).collect()
}

/// `domain.Matcher`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matcher {
    set: SuccinctSet,
}

fn with_label(label: u8, text: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(text.len() + 1);
    key.push(label);
    key.extend_from_slice(text);
    key
}

impl Matcher {
    /// `domain.NewMatcher`; `legacy` writes suffixes the way rule-set
    /// version 1 does.
    pub fn new(domains: &[String], suffixes: &[String], legacy: bool) -> Self {
        let mut seen = std::collections::HashSet::new();
        let mut list: Vec<Vec<u8>> = Vec::with_capacity(domains.len() + 2 * suffixes.len());
        for suffix in suffixes {
            if !seen.insert(suffix.clone()) {
                continue;
            }
            let bytes = suffix.as_bytes();
            if bytes.first() == Some(&b'.') {
                list.push(reverse_domain(&with_label(PREFIX_LABEL, bytes)));
            } else if legacy {
                list.push(reverse_domain(bytes));
                let dotted = format!(".{suffix}");
                if seen.insert(dotted.clone()) {
                    list.push(reverse_domain(&with_label(PREFIX_LABEL, dotted.as_bytes())));
                }
            } else {
                list.push(reverse_domain(&with_label(ROOT_LABEL, bytes)));
            }
        }
        for domain in domains {
            if !seen.insert(domain.clone()) {
                continue;
            }
            list.push(reverse_domain(domain.as_bytes()));
        }
        list.sort();
        list.dedup();
        Matcher { set: SuccinctSet::new(&list) }
    }

    pub fn read(reader: &mut Reader) -> Result<Self, ReadError> {
        Ok(Matcher { set: SuccinctSet::read(reader)? })
    }

    pub fn write(&self, buffer: &mut Vec<u8>) {
        self.set.write(buffer)
    }

    pub fn matches(&self, domain: &str) -> bool {
        self.has(&reverse_domain(domain.as_bytes())).unwrap_or(false)
    }

    fn has(&self, key: &[u8]) -> Option<bool> {
        let set = &self.set;
        let (mut node, mut bitmap_index) = (0usize, 0usize);
        for &current in key {
            loop {
                if set.is_end(bitmap_index) {
                    return Some(false);
                }
                let next = set.label(bitmap_index, node)?;
                if next == PREFIX_LABEL {
                    return Some(true);
                }
                if next == ROOT_LABEL {
                    let next_node = set.count_zeros(bitmap_index + 1)?;
                    if current == b'.' && set.is_leaf(next_node) {
                        return Some(true);
                    }
                }
                if next == current {
                    break;
                }
                bitmap_index += 1;
            }
            (node, bitmap_index) = set.child(bitmap_index)?;
        }
        if set.is_leaf(node) {
            return Some(true);
        }
        loop {
            if set.is_end(bitmap_index) {
                return Some(false);
            }
            let next = set.label(bitmap_index, node)?;
            if next == PREFIX_LABEL || next == ROOT_LABEL {
                return Some(true);
            }
            bitmap_index += 1;
        }
    }

    /// `Matcher.Dump`: the domains and suffixes, each sorted.
    pub fn dump(&self) -> (Vec<String>, Vec<String>) {
        let mut domains = std::collections::HashSet::new();
        let mut prefixes = std::collections::HashSet::new();
        let mut suffix_list = Vec::new();
        for key in self.set.keys() {
            let key = reverse_domain(&key);
            match key.first() {
                Some(&PREFIX_LABEL) => {
                    prefixes.insert(key[1..].to_vec());
                }
                Some(&ROOT_LABEL) => suffix_list.push(key[1..].to_vec()),
                _ => {
                    domains.insert(key);
                }
            }
        }
        for prefix in prefixes {
            if prefix.first() == Some(&b'.') {
                let root = prefix[1..].to_vec();
                if domains.remove(&root) {
                    suffix_list.push(root);
                    continue;
                }
            }
            suffix_list.push(prefix);
        }
        let mut domain_list: Vec<Vec<u8>> = domains.into_iter().collect();
        domain_list.sort();
        suffix_list.sort();
        let text = |list: Vec<Vec<u8>>| list.into_iter().map(|key| String::from_utf8_lossy(&key).into_owned()).collect();
        (text(domain_list), text(suffix_list))
    }
}

/// `domain.AdGuardMatcher`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdGuardMatcher {
    set: SuccinctSet,
}

impl AdGuardMatcher {
    /// `domain.NewAdGuardMatcher`.
    pub fn new(rule_lines: &[String]) -> Self {
        let mut list: Vec<Vec<u8>> = Vec::with_capacity(rule_lines.len());
        for line in rule_lines {
            let mut line = line.as_str();
            let mut is_suffix = false;
            let mut has_start = false;
            let mut has_end = false;
            if let Some(rest) = line.strip_prefix("||") {
                line = rest;
                is_suffix = true;
            } else if let Some(rest) = line.strip_prefix('|') {
                line = rest;
                has_start = true;
            }
            if let Some(rest) = line.strip_suffix('^') {
                line = rest;
                has_end = true;
            }
            let mut key: Vec<u8> = if is_suffix {
                with_label(ROOT_LABEL, line.as_bytes())
            } else if !has_start {
                with_label(PREFIX_LABEL, line.as_bytes())
            } else {
                line.as_bytes().to_vec()
            };
            if !has_end {
                if key.last() == Some(&b'.') {
                    key.pop();
                }
                key.push(SUFFIX_LABEL);
            }
            list.push(reverse_domain(&key));
        }
        list.sort();
        list.dedup();
        AdGuardMatcher { set: SuccinctSet::new(&list) }
    }

    pub fn read(reader: &mut Reader) -> Result<Self, ReadError> {
        Ok(AdGuardMatcher { set: SuccinctSet::read(reader)? })
    }

    pub fn write(&self, buffer: &mut Vec<u8>) {
        self.set.write(buffer)
    }

    pub fn matches(&self, domain: &str) -> bool {
        let mut key = reverse_domain(domain.as_bytes());
        if self.has(&key, 0, 0, 0).unwrap_or(false) {
            return true;
        }
        loop {
            if self.has(&with_label(SUFFIX_LABEL, &key), 0, 0, 0).unwrap_or(false) {
                return true;
            }
            match key.iter().position(|&byte| byte == b'.') {
                Some(index) => key = key[index + 1..].to_vec(),
                None => return false,
            }
        }
    }

    /// `hasWithDepth`.
    fn has(&self, key: &[u8], mut node: usize, mut bitmap_index: usize, depth: usize) -> Option<bool> {
        if depth > 100 {
            return Some(false);
        }
        let set = &self.set;
        for (i, &current) in key.iter().enumerate() {
            loop {
                if set.is_end(bitmap_index) {
                    return Some(false);
                }
                let next = set.label(bitmap_index, node)?;
                if next == PREFIX_LABEL {
                    return Some(true);
                }
                if next == ROOT_LABEL {
                    let next_node = set.count_zeros(bitmap_index + 1)?;
                    if current == b'.' && set.is_leaf(next_node) {
                        return Some(true);
                    }
                }
                if next == current {
                    break;
                }
                if next == ANY_LABEL || next == SUFFIX_LABEL {
                    let (next_node, next_index) = set.child(bitmap_index)?;
                    if self.has(&key[i..], next_node, next_index, depth + 1)? {
                        return Some(true);
                    }
                    for j in i + 1..=key.len() {
                        if self.has(&key[j..], next_node, next_index, depth + 1)? {
                            return Some(true);
                        }
                    }
                }
                bitmap_index += 1;
            }
            (node, bitmap_index) = set.child(bitmap_index)?;
        }
        if set.is_leaf(node) {
            return Some(true);
        }
        loop {
            if set.is_end(bitmap_index) {
                return Some(false);
            }
            let next = set.label(bitmap_index, node)?;
            if next == PREFIX_LABEL || next == ROOT_LABEL || next == SUFFIX_LABEL {
                return Some(true);
            }
            if next == ANY_LABEL {
                let (next_node, next_index) = set.child(bitmap_index)?;
                return self.has(&[], next_node, next_index, depth + 1);
            }
            bitmap_index += 1;
        }
    }

    /// `AdGuardMatcher.Dump`.
    pub fn dump(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for key in self.set.keys() {
            let mut key = reverse_domain(&key);
            if key.is_empty() {
                continue;
            }
            let mut is_suffix = false;
            let mut has_start = false;
            let mut has_end = false;
            match key[0] {
                PREFIX_LABEL => {
                    key.remove(0);
                }
                ROOT_LABEL => {
                    key.remove(0);
                    is_suffix = true;
                }
                _ => has_start = true,
            }
            if key.last() == Some(&SUFFIX_LABEL) {
                key.pop();
            } else {
                has_end = true;
            }
            let mut line = String::from_utf8_lossy(&key).into_owned();
            if is_suffix {
                line = format!("||{line}");
            } else if has_start {
                line = format!("|{line}");
            }
            if has_end {
                line.push('^');
            }
            lines.push(line);
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn matcher_semantics() {
        let matcher = Matcher::new(&strings(&["exact.com"]), &strings(&["example.com", ".cn", "sub.org"]), false);
        assert!(matcher.matches("exact.com"));
        assert!(!matcher.matches("www.exact.com"));
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("a.b.example.com"));
        assert!(!matcher.matches("badexample.com"));
        assert!(matcher.matches("baidu.cn"));
        assert!(!matcher.matches("cn"));
        assert!(matcher.matches("x.sub.org"));
        assert!(!matcher.matches("org"));
        let (domains, suffixes) = matcher.dump();
        assert_eq!(domains, strings(&["exact.com"]));
        assert_eq!(suffixes, strings(&[".cn", "example.com", "sub.org"]));
        // Version 1 stores a suffix as the domain plus a dotted suffix.
        let legacy = Matcher::new(&[], &strings(&["example.com"]), true);
        assert!(legacy.matches("example.com") && legacy.matches("a.example.com"));
        assert!(!legacy.matches("aexample.com"));
        assert_eq!(legacy.dump(), (vec![], strings(&["example.com"])));
    }

    #[test]
    fn matcher_round_trip() {
        let domains: Vec<String> = (0..500).map(|i| format!("host{i}.example{}.com", i % 7)).collect();
        let suffixes: Vec<String> = (0..300).map(|i| format!("zone{i}.net")).collect();
        let matcher = Matcher::new(&domains, &suffixes, false);
        let mut buffer = Vec::new();
        matcher.write(&mut buffer);
        let read = Matcher::read(&mut Reader::new(&buffer)).unwrap();
        assert_eq!(read, matcher);
        for domain in &domains {
            assert!(read.matches(domain), "{domain}");
        }
        assert!(read.matches("a.zone299.net"));
        assert!(!read.matches("host1.example2.com"));
        let (mut dumped_domains, dumped_suffixes) = read.dump();
        let mut sorted = domains.clone();
        sorted.sort();
        dumped_domains.sort();
        assert_eq!(dumped_domains, sorted);
        assert_eq!(dumped_suffixes.len(), 300);
    }

    #[test]
    fn malformed_set() {
        // version byte, no leaves, a bitmap with a single word of zeros, no labels
        let mut buffer = vec![0u8, 0, 1];
        buffer.extend_from_slice(&0u64.to_be_bytes());
        buffer.push(0);
        assert!(SuccinctSet::read(&mut Reader::new(&buffer)).is_err());
        assert!(SuccinctSet::read(&mut Reader::new(&[0, 0, 0, 0])).is_err());
    }

    #[test]
    fn adguard() {
        let matcher = AdGuardMatcher::new(&strings(&["||example.org^", "|exact.net^", "ads.", "*.tracker.io^"]));
        assert!(matcher.matches("example.org"));
        assert!(matcher.matches("www.example.org"));
        assert!(!matcher.matches("notexample.org"));
        assert!(matcher.matches("exact.net"));
        assert!(!matcher.matches("www.exact.net"));
        assert!(matcher.matches("ads.example.com"));
        assert!(matcher.matches("a.b.tracker.io"));
        let mut dumped = matcher.dump();
        dumped.sort();
        let mut expected = strings(&["||example.org^", "|exact.net^", "ads", "*.tracker.io^"]);
        expected.sort();
        assert_eq!(dumped, expected);
    }

    #[test]
    fn reverse() {
        assert_eq!(reverse_domain(b"abc.de"), b"ed.cba");
        assert_eq!(reverse_domain("中文.cn".as_bytes()), "nc.文中".as_bytes());
    }
}
