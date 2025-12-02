//! Input ownership mapping between garbler and evaluator.

use crate::gc::party::Party;

/// Describes contiguous input spans for each party.
#[derive(Clone, Debug)]
pub struct InputMap {
    /// Starting index for garbler inputs.
    pub garbler_offset: usize,
    /// Number of garbler inputs.
    pub garbler_len: usize,
    /// Starting index for evaluator inputs.
    pub evaluator_offset: usize,
    /// Number of evaluator inputs.
    pub evaluator_len: usize,
}

impl InputMap {
    /// Create a new input map given counts for each party.
    pub fn new(garbler_len: usize, evaluator_len: usize) -> Self {
        Self {
            garbler_offset: 0,
            garbler_len,
            evaluator_offset: garbler_len,
            evaluator_len,
        }
    }

    /// Return the wire indices for a given party.
    pub fn indices(&self, party: Party) -> Vec<usize> {
        match party {
            Party::Garbler => {
                (self.garbler_offset..self.garbler_offset + self.garbler_len).collect()
            }
            Party::Evaluator => {
                (self.evaluator_offset..self.evaluator_offset + self.evaluator_len).collect()
            }
        }
    }
}
