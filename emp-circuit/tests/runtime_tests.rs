use emp_circuit::gc::{
    evaluator::HalfGateEvaluator,
    garbler::HalfGateGarbler,
    mock_io::MockIO,
    party::Party,
    privacy_free::{PrivacyFreeEvaluator, PrivacyFreeGarbler},
    protocol::{set_thread_local_execs, set_thread_local_evaluator, set_thread_local_garbler},
};
use emp_circuit::core::protocol_runtime::{clear_executors, with_circuit_exec, with_protocol_exec};
use std::sync::{Arc, Barrier, mpsc::channel};
use std::thread;

#[test]
fn runtime_halfgate_roundtrip_and() {
    let (gio, eio) = MockIO::pair();
    let barrier = Arc::new(Barrier::new(2));
    let (tx_g, rx_g) = channel();
    let (tx_e, rx_e) = channel();

    let b1 = barrier.clone();
    let garbler = thread::spawn(move || {
        let g = HalfGateGarbler::new(gio, 2);
        let _handle = set_thread_local_garbler(g);
        // Feed evaluator-owned inputs (true, false).
        let lbls = with_protocol_exec(|p| p.feed(Party::Evaluator, &[true, false]));
        b1.wait();
        let out = with_circuit_exec(|c| c.and_gate(lbls[0], lbls[1]));
        tx_g.send(out).unwrap();
        clear_executors();
    });

    let b2 = barrier.clone();
    let evaluator = thread::spawn(move || {
        let e = HalfGateEvaluator::new(eio);
        let _handle = set_thread_local_evaluator(e);
        // Receive the two evaluator inputs.
        let lbls = with_protocol_exec(|p| p.feed(Party::Evaluator, &[false, false]));
        b2.wait();
        let out = with_circuit_exec(|c| c.and_gate(lbls[0], lbls[1]));
        tx_e.send(out).unwrap();
        clear_executors();
    });

    let garbler_out = rx_g.recv().unwrap();
    let evaluator_out = rx_e.recv().unwrap();
    garbler.join().unwrap();
    evaluator.join().unwrap();

    // Inputs (true, false) => output false, so evaluator label should match garbler's w0.
    assert_eq!(garbler_out, evaluator_out);
}

#[test]
fn runtime_privacy_free_roundtrip_multi_output() {
    // Circuit: out0 = a & b, out1 = a ^ b
    let mut c = emp_circuit::Circuit::new();
    let a = c.fresh_wire();
    let b = c.fresh_wire();
    let _and_out = c.and(a, b);
    let _xor_out = c.xor(a, b);

    let (gio, eio) = MockIO::pair();
    let barrier = Arc::new(Barrier::new(2));
    let (tx_g, rx_g) = channel();
    let (tx_e, rx_e) = channel();

    let c_g = c.clone();
    let b1 = barrier.clone();
    let g_thread = thread::spawn(move || {
        let g = PrivacyFreeGarbler::new(gio, c_g.wire_count());
        let rc = std::rc::Rc::new(std::cell::RefCell::new(g));
        set_thread_local_execs(rc.clone(), rc.clone());
        // Feed inputs: send both labels via evaluator channel for simplicity.
        let vals = with_protocol_exec(|p| p.feed(Party::Evaluator, &[false, false]));
        b1.wait();
        let out_and = with_circuit_exec(|c| c.and_gate(vals[0], vals[1]));
        let out_xor = with_circuit_exec(|c| c.xor_gate(vals[0], vals[1]));
        tx_g.send((out_and, out_xor)).unwrap();
        clear_executors();
    });

    let b2 = barrier.clone();
    let e_thread = thread::spawn(move || {
        let e = PrivacyFreeEvaluator::new(eio);
        let rc = std::rc::Rc::new(std::cell::RefCell::new(e));
        set_thread_local_execs(rc.clone(), rc.clone());
        let vals = with_protocol_exec(|p| p.feed(Party::Evaluator, &[false, false]));
        b2.wait();
        let out_and = with_circuit_exec(|c| c.and_gate(vals[0], vals[1]));
        let out_xor = with_circuit_exec(|c| c.xor_gate(vals[0], vals[1]));
        tx_e.send((out_and, out_xor)).unwrap();
        clear_executors();
    });

    let (g_and, g_xor) = rx_g.recv().unwrap();
    let (e_and, e_xor) = rx_e.recv().unwrap();
    g_thread.join().unwrap();
    e_thread.join().unwrap();

    // Inputs (false, false) => (and=false, xor=false)
    assert_eq!(g_and, e_and);
    assert_ne!(g_and, g_and ^ emp_tool::Block::ONES);
    assert_eq!(g_xor, e_xor);
}
