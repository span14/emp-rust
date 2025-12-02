/// Truth table accessor used by the unary outer product.
pub trait Table {
    /// Return the table row (as a bitmask) for the given index.
    fn row(&self, index: usize) -> usize;
}

/// Identity table `f(i) = i`.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdentityTable;

impl Table for IdentityTable {
    #[inline(always)]
    fn row(&self, index: usize) -> usize {
        index
    }
}
