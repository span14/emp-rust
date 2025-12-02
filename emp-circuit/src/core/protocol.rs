//! Protocol execution trait, mirroring EMP pattern (feed/reveal stubs).

use crate::core::wire::Wire;

/// Protocol execution interface (to be implemented by GC backends).
pub trait ProtocolExecution {
    /// Feed input labels for a party.
    fn feed(&mut self, _labels: &mut [Wire], _party: usize, _values: &[bool]) {}
    /// Reveal labels to a party.
    fn reveal(&mut self, _out: &mut [bool], _party: usize, _labels: &[Wire]) {}
}
