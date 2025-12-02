//! Protocol-like abstraction for feeding inputs and revealing outputs.

use crate::core::{circuit::Circuit, protocol_runtime::set_executors};
use crate::gc::{evaluator::HalfGateEvaluator, garbler::HalfGateGarbler, party::Party};
use std::cell::RefCell;
use std::rc::Rc;

/// Simplified protocol interface for GC sides.
pub trait GcProtocol {
    /// Feed inputs for a given party.
    fn feed_inputs(&mut self, party: Party, wire_indices: &[usize], bits: &[bool]);
    /// Process the circuit (garble or evaluate).
    fn process(&mut self, circuit: &Circuit);
    /// Reveal outputs; garbler decodes, evaluator sends labels back.
    fn reveal_outputs(&mut self, outputs: &[usize], decoder: Option<&crate::gc::label::OutputDecoder>) -> Vec<bool>;
    /// Return an `OutputDecoder` if held locally (garbler side).
    fn output_decoder(&self) -> Option<crate::gc::label::OutputDecoder> {
        None
    }
}

impl<IO: emp_tool::IOChannel> GcProtocol for HalfGateGarbler<IO> {
    fn feed_inputs(&mut self, party: Party, wire_indices: &[usize], bits: &[bool]) {
        self.feed(party, wire_indices, bits);
    }

    fn process(&mut self, circuit: &Circuit) {
        self.garble(circuit);
    }

    fn reveal_outputs(&mut self, outputs: &[usize], _decoder: Option<&crate::gc::label::OutputDecoder>) -> Vec<bool> {
        self.set_outputs(outputs);
        self.reveal(outputs)
    }

    fn output_decoder(&self) -> Option<crate::gc::label::OutputDecoder> {
        Some(self.decoder().clone())
    }
}

impl<IO: emp_tool::IOChannel> GcProtocol for HalfGateEvaluator<IO> {
    fn feed_inputs(&mut self, party: Party, wire_indices: &[usize], _bits: &[bool]) {
        self.feed(party, wire_indices);
    }

    fn process(&mut self, circuit: &Circuit) {
        self.evaluate(circuit);
    }

    fn reveal_outputs(&mut self, outputs: &[usize], decoder: Option<&crate::gc::label::OutputDecoder>) -> Vec<bool> {
        let lbls = self.send_outputs(outputs);
        if let Some(dec) = decoder {
            dec.decode_all(&lbls)
        } else {
            vec![false; lbls.len()]
        }
    }
}

/// Install a half-gate garbler as the global protocol/circuit executor (thread-local).
pub fn set_thread_local_garbler<IO: emp_tool::IOChannel + 'static>(
    garbler: HalfGateGarbler<IO>,
) -> Rc<RefCell<HalfGateGarbler<IO>>> {
    let rc = Rc::new(RefCell::new(garbler));
    set_executors(rc.clone(), rc.clone());
    rc
}

/// Install a half-gate evaluator as the global protocol/circuit executor (thread-local).
pub fn set_thread_local_evaluator<IO: emp_tool::IOChannel + 'static>(
    evaluator: HalfGateEvaluator<IO>,
) -> Rc<RefCell<HalfGateEvaluator<IO>>> {
    let rc = Rc::new(RefCell::new(evaluator));
    set_executors(rc.clone(), rc.clone());
    rc
}

/// Generic setter for any garbler/evaluator pair implementing both runtime traits.
pub fn set_thread_local_execs<P, C>(prot: Rc<RefCell<P>>, circ: Rc<RefCell<C>>)
where
    P: crate::core::protocol_runtime::ProtocolExecution + 'static,
    C: crate::core::protocol_runtime::CircuitExecution + 'static,
{
    set_executors(prot, circ);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gc::mock_io::MockIO;
    use crate::gc::party::Party;
    use emp_tool::Block;

    #[test]
    fn install_and_clear_executors() {
        let (gio, eio) = MockIO::pair();
        let g = HalfGateGarbler::new(gio, 1);
        let e = HalfGateEvaluator::new(eio);
        let _g_handle = set_thread_local_garbler(g);
        let _e_handle = set_thread_local_evaluator(e);
        crate::core::protocol_runtime::PROT_EXEC.with(|p| {
            assert!(p.borrow().is_some());
        });
        crate::core::protocol_runtime::CIRC_EXEC.with(|c| {
            assert!(c.borrow().is_some());
        });
        // Call reveal via protocol executor to ensure trait object dispatch works.
        crate::core::protocol_runtime::PROT_EXEC.with(|p| {
            let binding = p.borrow();
            let mut prot = binding.as_ref().unwrap().borrow_mut();
            let _ = prot.reveal(Party::Evaluator, &[Block::ZERO]);
        });
        crate::core::protocol_runtime::clear_executors();
        crate::core::protocol_runtime::PROT_EXEC.with(|p| {
            assert!(p.borrow().is_none());
        });
        crate::core::protocol_runtime::CIRC_EXEC.with(|c| {
            assert!(c.borrow().is_none());
        });
    }
}
