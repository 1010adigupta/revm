use crate::{Account, Address, HashMap, B256};
use auto_impl::auto_impl;


/// EVM verkledatabase interface.
#[auto_impl(&mut, Box)]
pub trait VerkleDatabase {
    /// The database error type.
    type Error;

    /// Get the leaf node for the given key
    fn get_leaf(&mut self, key: B256) -> Result<Option<B256>, Self::Error>;
}

/// EVM database commit interface.
#[auto_impl(&mut, Box)]
pub trait VerkleDatabaseCommit {
    /// Commit changes to the database.
    fn commit(&mut self, changes: HashMap<Address, Account>);
}

/// EVM database interface.
///
/// Contains the same methods as [`VerkleDatabase`], but with `&self` receivers instead of `&mut self`.
///
/// Use [`WrapVerkleDatabaseRef`] to provide [`VerkleDatabase`] implementation for a type
/// that only implements this trait.
#[auto_impl(&, &mut, Box, Rc, Arc)]
pub trait VerkleDatabaseRef {
    /// The database error type.
    type Error;

    /// Get the leaf node for the given key
    fn get_leaf_ref(&self, key: B256) -> Result<Option<B256>, Self::Error>;
}

/// Wraps a [`VerkleDatabaseRef`] to provide a [`VerkleDatabase`] implementation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WrapVerkleDatabaseRef<T: VerkleDatabaseRef>(pub T);

impl<F: VerkleDatabaseRef> From<F> for WrapVerkleDatabaseRef<F> {
    #[inline]
    fn from(f: F) -> Self {
        WrapVerkleDatabaseRef(f)
    }
}

impl<T: VerkleDatabaseRef> VerkleDatabase for WrapVerkleDatabaseRef<T> {
    type Error = T::Error;

    #[inline]
    fn get_leaf(&mut self, key: B256) -> Result<Option<B256>, Self::Error> {
        self.0.get_leaf_ref(key)
    }
}

impl<T: VerkleDatabaseRef + VerkleDatabaseCommit> VerkleDatabaseCommit for WrapVerkleDatabaseRef<T> {
    #[inline]
    fn commit(&mut self, changes: HashMap<Address, Account>) {
        self.0.commit(changes)
    }
}