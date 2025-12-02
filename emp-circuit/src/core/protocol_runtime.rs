//! Simple protocol/circuit execution traits with global handles, akin to EMP's API.

use crate::gc::party::Party;
use emp_tool::Block;
use std::cell::RefCell;
use std::rc::Rc;

/// Trait for feeding inputs and revealing outputs.
pub trait ProtocolExecution {
    /// Feed `bits` for `party` into labels.
    fn feed(&mut self, party: Party, bits: &[bool]) -> Vec<Block>;
    /// Reveal labels to `party`, returning clear bits.
    fn reveal(&mut self, party: Party, labels: &[Block]) -> Vec<bool>;
}

/// Trait for executing gates.
pub trait CircuitExecution {
    /// Compute a garbled AND on two labels.
    fn and_gate(&mut self, a: Block, b: Block) -> Block;
    /// Compute a garbled XOR on two labels.
    fn xor_gate(&mut self, a: Block, b: Block) -> Block;
    /// Compute a garbled NOT on a label.
    fn not_gate(&mut self, a: Block) -> Block;
    /// Return the public label representing `b`.
    fn public_label(&self, b: bool) -> Block;
}

thread_local! {
    /// Thread-local protocol executor used by higher-level runtimes.
    pub static PROT_EXEC: RefCell<Option<Rc<RefCell<dyn ProtocolExecution>>>> = RefCell::new(None);
    /// Thread-local circuit executor used by higher-level runtimes.
    pub static CIRC_EXEC: RefCell<Option<Rc<RefCell<dyn CircuitExecution>>>> = RefCell::new(None);
}

/// Set the current protocol and circuit executors.
pub fn set_executors(
    prot: Rc<RefCell<dyn ProtocolExecution>>,
    circ: Rc<RefCell<dyn CircuitExecution>>,
) {
    PROT_EXEC.with(|p| *p.borrow_mut() = Some(prot));
    CIRC_EXEC.with(|c| *c.borrow_mut() = Some(circ));
}

/// Clear executors (for tests).
pub fn clear_executors() {
    PROT_EXEC.with(|p| *p.borrow_mut() = None);
    CIRC_EXEC.with(|c| *c.borrow_mut() = None);
}

/// Borrow the current protocol executor and run a closure on it.
pub fn with_protocol_exec<R, F: FnOnce(&mut dyn ProtocolExecution) -> R>(f: F) -> R {
    PROT_EXEC.with(|p| {
        let rc = p
            .borrow()
            .as_ref()
            .expect("protocol executor not set")
            .clone();
        let mut guard = rc.borrow_mut();
        f(&mut *guard)
    })
}

/// Borrow the current circuit executor and run a closure on it.
pub fn with_circuit_exec<R, F: FnOnce(&mut dyn CircuitExecution) -> R>(f: F) -> R {
    CIRC_EXEC.with(|c| {
        let rc = c
            .borrow()
            .as_ref()
            .expect("circuit executor not set")
            .clone();
        let mut guard = rc.borrow_mut();
        f(&mut *guard)
    })
}
