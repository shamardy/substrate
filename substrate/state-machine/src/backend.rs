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

//! State machine backends. These manage the code and storage of contracts.

use std::{error, fmt};
use std::collections::HashMap;
use std::sync::Arc;
use changes_trie::{ChangesTrieStorage, ChangesTrieNode, compute_changes_trie_root};
use overlayed_changes::OverlayedChanges;
use trie_backend::{TryIntoTrieBackend, TrieBackend};

/// A state backend is used to read state data and can have changes committed
/// to it.
///
/// The clone operation (if implemented) should be cheap.
pub trait Backend: TryIntoTrieBackend {
	/// An error type when fetching data is not possible.
	type Error: super::Error;

	/// Storage changes to be applied if committing
	type StorageTransaction;
	/// Changes to changes trie to be applied if committing.
	type ChangesTrieTransaction;

	/// Get reference to read-only changes trie storage.
	fn changes_trie_storage(&self) -> Option<&ChangesTrieStorage>;

	/// Get keyed storage associated with specific address, or None if there is nothing associated.
	fn storage(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

	/// true if a key exists in storage.
	fn exists_storage(&self, key: &[u8]) -> Result<bool, Self::Error> {
		Ok(self.storage(key)?.is_some())
	}

	/// Retrieve all entries keys of which start with the given prefix and
	/// call `f` for each of those keys.
	fn for_keys_with_prefix<F: FnMut(&[u8])>(&self, prefix: &[u8], f: F);

	/// Calculate the storage root, with given delta over what is already stored in
	/// the backend, and produce a "transaction" that can be used to commit.
	fn storage_root<I>(&self, delta: I) -> ([u8; 32], Self::StorageTransaction)
		where I: IntoIterator<Item=(Vec<u8>, Option<Vec<u8>>)>;

	/// Calculate the changes trie root for given overlay and produce a "transaction"
	/// that can be used to commit.
	fn changes_trie_root(&self, overlay: &OverlayedChanges) -> Option<([u8; 32], Self::ChangesTrieTransaction)>;

	/// Get all key/value pairs into a Vec.
	fn pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)>;
}

/// Error impossible.
// TODO: use `!` type when stabilized.
#[derive(Debug)]
pub enum Void {}

impl fmt::Display for Void {
	fn fmt(&self, _: &mut fmt::Formatter) -> fmt::Result {
		match *self {}
	}
}

impl error::Error for Void {
	fn description(&self) -> &str { "unreachable error" }
}

/// In-memory backend. Fully recomputes tries on each commit but useful for
/// tests.
#[derive(Clone, PartialEq, Eq)]
pub struct InMemory {
	inner: Arc<HashMap<Vec<u8>, Vec<u8>>>,
	changes_trie_storage: HashMap<u64, Vec<ChangesTrieNode>>,
}

impl Default for InMemory {
	fn default() -> Self {
		InMemory {
			inner: Arc::new(Default::default()),
			changes_trie_storage: Default::default(),
		}
	}
}

impl InMemory {
	/// Create in-memory backend with given changes_trie_storage.
	pub fn with_changes_trie_storage(changes_trie_storage: HashMap<u64, Vec<ChangesTrieNode>>) -> Self {
		InMemory {
			inner: Default::default(),
			changes_trie_storage,
		}
	}

	/// Copy the state, with applied updates
	pub fn update(&self, changes: <Self as Backend>::StorageTransaction) -> Self {
		let mut inner: HashMap<_, _> = (&*self.inner).clone();
		for (key, val) in changes {
			match val {
				Some(v) => { inner.insert(key, v); },
				None => { inner.remove(&key); },
			}
		}

		inner.into()
	}
}

impl From<HashMap<Vec<u8>, Vec<u8>>> for InMemory {
	fn from(inner: HashMap<Vec<u8>, Vec<u8>>) -> Self {
		InMemory {
			inner: Arc::new(inner),
			changes_trie_storage: Default::default(),
		}
	}
}

impl super::Error for Void {}

impl Backend for InMemory {
	type Error = Void;
	type StorageTransaction = Vec<(Vec<u8>, Option<Vec<u8>>)>;
	type ChangesTrieTransaction = Vec<(Vec<u8>, Vec<u8>)>;

	fn changes_trie_storage(&self) -> Option<&ChangesTrieStorage> {
		Some(self)
	}

	fn storage(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
		Ok(self.inner.get(key).map(Clone::clone))
	}

	fn exists_storage(&self, key: &[u8]) -> Result<bool, Self::Error> {
		Ok(self.inner.get(key).is_some())
	}

	fn for_keys_with_prefix<F: FnMut(&[u8])>(&self, prefix: &[u8], f: F) {
		self.inner.keys().filter(|key| key.starts_with(prefix)).map(|k| &**k).for_each(f);
	}

	fn storage_root<I>(&self, delta: I) -> ([u8; 32], Self::StorageTransaction)
		where I: IntoIterator<Item=(Vec<u8>, Option<Vec<u8>>)>
	{
		let existing_pairs = self.inner.iter().map(|(k, v)| (k.clone(), Some(v.clone())));

		let transaction: Vec<_> = delta.into_iter().collect();
		let root = ::triehash::trie_root(existing_pairs.chain(transaction.iter().cloned())
			.collect::<HashMap<_, _>>()
			.into_iter()
			.filter_map(|(k, maybe_val)| maybe_val.map(|val| (k, val)))
		).0;

		(root, transaction)
	}

	fn changes_trie_root(&self, overlay: &OverlayedChanges) -> Option<([u8; 32], Self::ChangesTrieTransaction)> {
		compute_changes_trie_root(self, overlay)
	}

	fn pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
		self.inner.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
	}
}

impl ChangesTrieStorage for InMemory {
	fn enumerate_trie_nodes(&self, block: u64) -> Box<Iterator<Item = ChangesTrieNode>> {
		Box::new(self.changes_trie_storage.get(&block).cloned().unwrap_or_default().into_iter())
	}
}

impl TryIntoTrieBackend for InMemory {
	fn try_into_trie_backend(self) -> Option<TrieBackend> {
		use ethereum_types::H256 as TrieH256;
		use memorydb::MemoryDB;
		use patricia_trie::{TrieDBMut, TrieMut};

		let mut root = TrieH256::default();
		let mut mdb = MemoryDB::default();
		{
			let mut trie = TrieDBMut::new(&mut mdb, &mut root);
			for (key, value) in self.inner.iter() {
				if let Err(e) = trie.insert(&key, &value) {
					warn!(target: "trie", "Failed to write to trie: {}", e);
					return None;
				}
			}
		}

		Some(TrieBackend::with_memorydb(mdb, root))
	}
}
