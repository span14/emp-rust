//! Plain (non-garbled) executors implementing the runtime traits for testing.

use crate::core::protocol_runtime::{CircuitExecution, ProtocolExecution};
use crate::gc::party::Party;
use emp_tool::Block;

/// Plain protocol executor: just stores bits.
pub struct PlainProtExec;

impl ProtocolExecution for PlainProtExec {
    fn feed(&mut self, _party: Party, bits: &[bool]) -> Vec<Block> {
        bits.iter().map(|b| if *b { Block::ONES } else { Block::ZERO }).collect()
    }

    fn reveal(&mut self, _party: Party, labels: &[Block]) -> Vec<bool> {
        labels.iter().map(|l| l.get_lsb()).collect()
    }
}

/// Plain circuit executor using Boolean ops on LSB.
pub struct PlainCircExec;

impl CircuitExecution for PlainCircExec {
    fn and_gate(&mut self, a: Block, b: Block) -> Block {
        if a.get_lsb() && b.get_lsb() { Block::ONES } else { Block::ZERO }
    }
    fn xor_gate(&mut self, a: Block, b: Block) -> Block {
        if a.get_lsb() ^ b.get_lsb() { Block::ONES } else { Block::ZERO }
    }
    fn not_gate(&mut self, a: Block) -> Block {
        if a.get_lsb() { Block::ZERO } else { Block::ONES }
    }
    fn public_label(&self, b: bool) -> Block {
        if b { Block::ONES } else { Block::ZERO }
    }
}
