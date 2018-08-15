// Copyright 2017 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! TODO

//#![allow(unused_must_use)]
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use codec::Encode;
use backend::Backend;
use overlayed_changes::OverlayedChanges;

/// Changes trie node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangesTrieNode {
	/// Node that contains mapping of modified key index to key.
	KeyIndex(u64, Vec<u8>),
	/// Node that contains mapping of key to the list of indices of
	/// this block extrinsics where it has been changed.
	ExtrinsicIndex(Vec<u8>, Vec<u32>),
	/// Node that contains mapping of key to the list of digests/blocks
	/// where it has been changed.
	DigestIndex(Vec<u8>, Vec<u64>),
}

/// Changes trie read-only storage.
pub trait ChangesTrieStorage {
	/// Run given callback for every trie pair.
	fn enumerate_trie_nodes(&self, block: u64) -> Box<Iterator<Item = ChangesTrieNode>>;
}

/// Configuration of changes trie.
#[derive(Clone, Debug)]
pub struct ChangesTrieConfig {
	/// Digest multiplier bit.
	pub digest_multiplier_bit: u8,
	/// Digest limit bit.
	pub digest_limit_bit: u8,
}

/// Digest build params.
#[derive(Debug, PartialEq)]
pub struct DigestBuildParams {
	/// Current block.
	current: u64,
	/// Begin block.
	begin: u64,
	/// Step.
	step: u64,
}

impl Iterator for DigestBuildParams {
	type Item = u64;

	fn next(&mut self) -> Option<Self::Item> {
		let next_current = self.current.saturating_sub(self.step);
		if next_current <= self.begin {
			None
		} else {
			self.current = next_current;
			Some(next_current)
		}
	}
}

impl ChangesTrieConfig {
	/// If given block requires to have digest, return digest build parameters.
	pub fn suggest_digest(&self, block: u64) -> Option<DigestBuildParams> {
		// never build digest for genesis block OR if multiplier bit is zero
		if block == 0 || self.digest_multiplier_bit == 0 {
			return None;
		}

		// build digest every digest_multiplier blocks
		let mut digest_level = 1u64 << self.digest_multiplier_bit;
		if block & (digest_level - 1) != 0 {
			return None;
		}

		let digest_limit = 1u64 << self.digest_limit_bit;
		let mut digest_step = 1u64;
		match digest_level.cmp(&digest_limit) {
			// initial level is greater than limit => no digest required
			::std::cmp::Ordering::Greater => return None,
			// initial level is equal to limit => single level digest
			::std::cmp::Ordering::Equal => (),
			// initial level is less than limit => check if next level(s) digest is required
			::std::cmp::Ordering::Less => {
				loop {
					let new_digest_level = digest_level << self.digest_multiplier_bit;
					if new_digest_level > digest_limit {
						break;
					}
					if block & (new_digest_level - 1) != 0 {
						break;
					}

					digest_level = new_digest_level;
					digest_step = digest_step << self.digest_multiplier_bit;
				}
			}
		}

		Some(DigestBuildParams {
			current: block,
			begin: block - digest_level,
			step: digest_step,
		})
	}
}

/// Compute changes trie root and transaction for given block.
pub fn compute_changes_trie_root<B: Backend>(
	backend: &B,
	changes: &OverlayedChanges,
) -> Option<([u8; 32], Vec<(Vec<u8>, Vec<u8>)>)> {
	let changes_trie_nodes = build_changes_trie_nodes(
		backend,
		changes)?;
	let transaction = changes_trie_nodes.into_iter()
		.map(ChangesTrieNode::into_pair)
		.collect::<Vec<_>>();
	let root = ::triehash::trie_root(transaction.iter().map(|(k, v)| (&*k, &*v))).0;

	Some((root, transaction))
}

/// Build changes trie nodes for the given block.
pub fn build_changes_trie_nodes<B: Backend>(
	backend: &B,
	changes: &OverlayedChanges,
) -> Option<Vec<ChangesTrieNode>> {
	let extrinsic_changes = changes.extrinsic_changes.as_ref()?;
	let storage = backend.changes_trie_storage()?;

	let mut nodes = Vec::new();

	// TODO: do not include temporary (whice were created and deleted in the same block) values

	// every changes trie contains mapping of { changed key index => key }, ending with sentinel element
	let mut key_count: u64 = 0;
	nodes.extend(changes.prospective.keys()
		.chain(changes.committed.keys())
		.collect::<BTreeSet<_>>()
		.into_iter()
		// assign index to each key
		.map(|key| ChangesTrieNode::KeyIndex({
			let key_index = key_count;
			key_count += 1;
			key_index
		}, key.clone())));
	nodes.push(ChangesTrieNode::KeyIndex(key_count, vec![]));

	// every changes trie contains mapping of { changes key => Set<extrinsic index it has been changed in> }
	let mut extrinsic_map = BTreeMap::<Vec<u8>, BTreeSet<u32>>::new();
	for (key, extrinsics) in extrinsic_changes.prospective.iter().chain(extrinsic_changes.committed.iter()) {
		extrinsic_map.entry(key.clone()).or_default()
			.extend(extrinsics);
	}
	nodes.extend(extrinsic_map.into_iter()
		.map(|(key, extrinsics)| ChangesTrieNode::ExtrinsicIndex(key.clone(), extrinsics.iter().cloned().collect())));

	// some changes tries also have digest subtree
	if let Some(digest_build_params) = extrinsic_changes.changes_trie_config.suggest_digest(extrinsic_changes.block) {
		let mut digest_nodes = BTreeMap::<Vec<u8>, BTreeSet<u64>>::new();
		for digest_build_block in digest_build_params {
			for node in storage.enumerate_trie_nodes(digest_build_block) {
				match node {
					ChangesTrieNode::ExtrinsicIndex(key, _) | ChangesTrieNode::DigestIndex(key, _) => {
						digest_nodes.entry(key).or_default()
							.insert(digest_build_block);
					},
					_ => (),
				}
			}
		}

		nodes.extend(digest_nodes.into_iter().map(|(key, set)| ChangesTrieNode::DigestIndex(key, set.into_iter().collect())));
	}

	Some(nodes)
}

impl ChangesTrieNode {
	/// Serializes trie node into trie pair.
	pub fn into_pair(self) -> (Vec<u8>, Vec<u8>) {
		match self {
			ChangesTrieNode::KeyIndex(idx, key) => (idx.encode(), key),
			ChangesTrieNode::ExtrinsicIndex(key, set) => (key, set.encode()),
			ChangesTrieNode::DigestIndex(key, set) => (key, set.encode()),
		}
	}
}

#[cfg(test)]
mod tests {
	use backend::InMemory;
	use overlayed_changes::ExtrinsicChanges;
	use super::*;

/*	type DummyStorage = HashMap<u64, Vec<ChangesTrieNode>>;

	impl ChangesTrieStorage for DummyStorage {
		fn enumerate_trie_nodes(&self, block: u64) -> Box<Iterator<Item = ChangesTrieNode>> {
			Box::new(self.get(&block).unwrap().clone().into_iter())
		}
	}*/

	fn suggest_digest(digest_multiplier_bit: u8, digest_limit_bit: u8, block: u64) -> Option<DigestBuildParams> {
		ChangesTrieConfig { digest_multiplier_bit, digest_limit_bit }.suggest_digest(block)
	}

	fn digest_build_params(current: u64, begin: u64, step: u64) -> Option<DigestBuildParams> {
		Some(DigestBuildParams { current, begin, step })
	}

	#[test]
	fn suggest_digest_returns_none() {
		assert_eq!(suggest_digest(0, 16, 64), None, "digest_multiplier_bit is 0");
		assert_eq!(suggest_digest(4, 16, 0), None, "block is 0");
		assert_eq!(suggest_digest(4, 16, 1), None, "digest is not required for this block");
		assert_eq!(suggest_digest(4, 16, 8), None, "digest is not required for this block");
		assert_eq!(suggest_digest(4, 16, 15), None, "digest is not required for this block");
		assert_eq!(suggest_digest(4, 16, 17), None, "digest is not required for this block");
		assert_eq!(suggest_digest(4, 3, 17), None, "digest is greater than limit");
	}

	#[test]
	fn suggest_digest_returns_some() {
		assert_eq!(suggest_digest(4, 4, 16), digest_build_params(16, 0, 1), "first digest level == digest limit");
		assert_eq!(suggest_digest(4, 5, 256), digest_build_params(256, 240, 1), "second digest level < digest limit");
		assert_eq!(suggest_digest(4, 8, 32), digest_build_params(32, 16, 1), "second level digest is not required for this block");
		assert_eq!(suggest_digest(4, 8, 256), digest_build_params(256, 0, 16), "second level digest");
		assert_eq!(suggest_digest(4, 9, 4096), digest_build_params(4096, 3840, 16), "third digest level < digest limit");
		assert_eq!(suggest_digest(4, 12, 4080), digest_build_params(4080, 4064, 1), "second && third level digest is not required for this block");
		assert_eq!(suggest_digest(4, 12, 4096), digest_build_params(4096, 0, 256), "third level digest: beginning");
		assert_eq!(suggest_digest(4, 12, 8192), digest_build_params(8192, 4096, 256), "third level digest: next");
	}

	fn prepare_for_build(block: u64) -> (InMemory, OverlayedChanges) {
		let backend = InMemory::with_changes_trie_storage(vec![
			(1, vec![
				ChangesTrieNode::KeyIndex(0, vec![100]),
				ChangesTrieNode::KeyIndex(1, vec![101]),
				ChangesTrieNode::KeyIndex(2, vec![105]),
				ChangesTrieNode::KeyIndex(3, vec![]),
				ChangesTrieNode::ExtrinsicIndex(vec![100], vec![1, 3]),
				ChangesTrieNode::ExtrinsicIndex(vec![101], vec![0, 2]),
				ChangesTrieNode::ExtrinsicIndex(vec![105], vec![0, 2, 4]),
			]),
			(2, vec![
				ChangesTrieNode::KeyIndex(0, vec![102]),
				ChangesTrieNode::KeyIndex(1, vec![]),
				ChangesTrieNode::ExtrinsicIndex(vec![102], vec![0]),
			]),
			(3, vec![
				ChangesTrieNode::KeyIndex(0, vec![100]),
				ChangesTrieNode::KeyIndex(1, vec![105]),
				ChangesTrieNode::KeyIndex(2, vec![]),
				ChangesTrieNode::ExtrinsicIndex(vec![100], vec![0]),
				ChangesTrieNode::ExtrinsicIndex(vec![105], vec![1]),
			]),
		].into_iter().collect());
		let changes = OverlayedChanges {
			prospective: vec![
				(vec![100], Some(vec![200])),
				(vec![103], None),
			].into_iter().collect(),
			committed: vec![
				(vec![100], Some(vec![202])),
				(vec![101], Some(vec![203])),
			].into_iter().collect(),
			extrinsic_changes: Some(ExtrinsicChanges {
				changes_trie_config: ChangesTrieConfig { digest_multiplier_bit: 2, digest_limit_bit: 4 },
				block,
				extrinsic_index: 0,
				prospective: vec![
					(vec![100], vec![0, 2].into_iter().collect()),
					(vec![103], vec![0, 1].into_iter().collect()),
				].into_iter().collect(),
				committed: vec![
					(vec![100], vec![3].into_iter().collect()),
					(vec![101], vec![1].into_iter().collect()),
				].into_iter().collect(),
			}),
		};

		(backend, changes)
	}

	#[test]
	fn build_changes_trie_nodes_on_non_digest_block() {
		let (backend, changes) = prepare_for_build(5);
		let changes_trie_nodes = build_changes_trie_nodes(&backend, &changes);
		assert_eq!(changes_trie_nodes, Some(vec![
			ChangesTrieNode::KeyIndex(0, vec![100]),
			ChangesTrieNode::KeyIndex(1, vec![101]),
			ChangesTrieNode::KeyIndex(2, vec![103]),
			ChangesTrieNode::KeyIndex(3, vec![]),
			ChangesTrieNode::ExtrinsicIndex(vec![100], vec![0, 2, 3]),
			ChangesTrieNode::ExtrinsicIndex(vec![101], vec![1]),
			ChangesTrieNode::ExtrinsicIndex(vec![103], vec![0, 1]),
		]));
	}

	#[test]
	fn build_changes_trie_nodes_on_digest_block_l1() {
		let (backend, changes) = prepare_for_build(4);
		let changes_trie_nodes = build_changes_trie_nodes(&backend, &changes);
		assert_eq!(changes_trie_nodes, Some(vec![
			ChangesTrieNode::KeyIndex(0, vec![100]),
			ChangesTrieNode::KeyIndex(1, vec![101]),
			ChangesTrieNode::KeyIndex(2, vec![103]),
			ChangesTrieNode::KeyIndex(3, vec![]),
			ChangesTrieNode::ExtrinsicIndex(vec![100], vec![0, 2, 3]),
			ChangesTrieNode::ExtrinsicIndex(vec![101], vec![1]),
			ChangesTrieNode::ExtrinsicIndex(vec![103], vec![0, 1]),

			ChangesTrieNode::DigestIndex(vec![100], vec![1, 3]),
			ChangesTrieNode::DigestIndex(vec![101], vec![1]),
			ChangesTrieNode::DigestIndex(vec![102], vec![2]),
			ChangesTrieNode::DigestIndex(vec![105], vec![1, 3]),
		]));
	}

	#[test]
	fn build_changes_trie_nodes_on_digest_block_l2() {
		// TODO
	}

	#[test]
	fn build_changes_trie_nodes_ignores_temporary_storage_values() {
		// TODO
	}
}




/*















/// Changes trie storage API.
pub trait ChangesTrieStorage {
	/// Read trie at given block.
	fn read(&self) -> Result<Box<ChangesTrie>, Error>;
}

pub struct KeyChangesIterator {

}

impl Iterator for KeyChangesIterator {
	
}

pub struct ChangesTrie {
	fn read_key_changes() -> KeyChangesIterator;
	//fn prove_key_changes() -> ProvableKeyChangesIterator;
}

/// Data for computing changes trie root .
pub struct BlockChanges {
	/// All keys that were changed in the block. Pre-sorted to avoid duplicates
	/// and ease indices computation.
	pub keys: BTreeSet<Vec<u8>>,
	/// Mapping of { key => set of extrinsic it is changed in }.
	pub extrinsics: HashMap<Vec<u8>, BTreeSet<u32>>,
}

/// Changes trie transaction.
pub type ChangesTrieTransaction = Vec<(Vec<u8>, Vec<u8>)>;

/// Changes trie input tuple.
enum ChangesNode {
	/// { storage key index => storage key } mapping tuple.
	KeyIndex((u64, Vec<u8>)),
	/// { storage key => extrinsic index } mapping tuple.
	ExtrinsicIndex((Vec<u8>, BTreeSet<u32>)),
	/// { storage key => block index } mapping tuple. If block at block index contains digest
	/// element, this node **could** mean that key has been modified in digest blocks (not the
	/// block itself).
	BlockIndex((Vec<u8>, BTreeSet<u64>)),
}

/// Calculate changes trie root and changes trie storage transaction
/// for given block and set of changes.
pub fn changes_trie_root(
	block: u64,
	multiplier: u64,
	limit: u64,
	changes: &BlockChanges,
	storage: &ChangesTrieStorage,
) -> ([u8; 32], ChangesTrieTransaction) {
	// insert all changed keys
	let mut key_count: u64 = 0;
	let mut keys_mapping = changes.keys.iter()
		// assign index to each key
		.map(|k| ChangesNode::StorageKeyIndex(({
			let key_index = key_count;
			key_count += 1;
			key_index
		}, k.clone())))
		.collect::<BTreeSet<_>>();

	// insert sentinel element
	pairs.insert(ChangesNode::StorageKeyIndex(key_count, vec![]);

	// insert key => extrinsics mapping
	for (key, extrinsics) in &changes.extrinsics {
		pairs.insert(ChangesNode::ExtrinsicIndex(key.clone(), extrinsics.clone()));
	}

	// if digest is required, insert digest fields
	if let Some((digest_level, digest_step)) = digest(block, multiplier) {
		let mut 
	}
}

/// Build changes trie input pairs.
fn build_changes_trie_input(
	block: u64,
	multiplier: u64,
	limit: u64,
	changes: &BlockChanges,
	storage: &ChangesTrieStorage,
) -> Vec<ChangesNode> {
	// insert all changed keys
	let mut key_count: u64 = 0;
	let mut input = changes.keys.iter()
		// assign index to each key
		.map(|k| ChangesNode::StorageKeyIndex(({
			let key_index = key_count;
			key_count += 1;
			key_index
		}, k.clone())))
		.collect::<BTreeSet<_>>();

	// insert sentinel element
	input.insert(ChangesNode::StorageKeyIndex(key_count, vec![]);

	// insert key => extrinsics mapping
	for (key, extrinsics) in &changes.extrinsics {
		input.insert(ChangesNode::ExtrinsicIndex(key.clone(), extrinsics.clone()));
	}

	// if digest is required, insert digest fields
	if let Some((digest_begin, digest_step)) = digest(block, multiplier) {
		input.extend(build_digest_input(block, digest_begin, digest_step, changes, storage));
	}

	input
}

fn build_digest_input(
	block: u64,
	digest_begin: u64,
	digest_step: u64,
	changes: &BlockChanges,
	storage: &ChangesTrieStorage,
) -> HashMap<Vec<u8>, HashMap<u64>> {
	// insert keys of this block
	let mut input = HashMap::new();
	for key in changes.keys.iter() {
		input.entry(key.clone()).or_default()
			.insert(block);
	}

	// insert keys from previous tries
	let mut trie_block = block - digest_step;
	loop {
		let trie = storage.for_each_trie_node(trie_block,
			ChangesNodeType::ExtrinsicIndex | ChangesNodeType::BlockIndex,
			|key| input.entry(key).or_default()
				.insert(trie_block));

		if trie_block == digest_begin {
			break;
		}

		trie_block = trie_block - digest_step;
	}

	input
}

/// Calculate digest step and number of steps for the given block.
/// None if digest element is not required at this block.
fn digest_step(block: u64, multiplier: u64, limit: u64) -> Option<(u64, u64)> {
	assert!(multiplier);

	if block == 0 || multiplier == 0 || block % multiplier != 0 {
		return None;
	}
}*/

