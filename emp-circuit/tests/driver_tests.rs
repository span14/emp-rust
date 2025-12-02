use emp_circuit::gc::{
    driver::{garble_and_eval, garble_and_eval_privacy_free, garble_and_eval_with_map},
    mock_io::MockIO,
};
use emp_circuit::Circuit;
use emp_tool::NetIO;
use rand::Rng;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

#[test]
fn driver_with_mock_io_multi_output() {
    // Circuit: two outputs: and = a&b, xor = a^b
    let mut c = Circuit::new();
    let a = c.fresh_wire();
    let b = c.fresh_wire();
    let and_out = c.and(a, b);
    let xor_out = c.xor(a, b);
    assert_eq!(and_out.id(), 2);
    assert_eq!(xor_out.id(), 3);

    let (gio, eio) = MockIO::pair();
    let bits = garble_and_eval(
        &c,
        &[true],
        &[false],
        gio,
        eio,
        &[and_out.id(), xor_out.id()],
    );
    assert_eq!(bits, vec![false, true]);
}

fn build_1bit_adder() -> (Circuit, usize, usize) {
    let mut c = Circuit::new();
    let a = c.fresh_wire();
    let b = c.fresh_wire();
    let sum = c.xor(a, b);
    let carry = c.and(a, b);
    (c, sum.id(), carry.id())
}

#[test]
fn driver_mock_io_random_inputs() {
    let (mut rng, trials) = (rand::rng(), 8);
    for _ in 0..trials {
        let (c, sum_idx, carry_idx) = build_1bit_adder();
        let a: bool = rng.random();
        let b: bool = rng.random();
        let (gio, eio) = MockIO::pair();
        let bits = garble_and_eval(&c, &[a], &[b], gio, eio, &[sum_idx, carry_idx]);
        assert_eq!(bits, vec![a ^ b, a & b]);
    }
}

#[test]
fn driver_netio_loopback() {
    // Use localhost TCP sockets for a simple loopback.
    let (c, sum_idx, carry_idx) = build_1bit_adder();
    let a = true;
    let b = true;
    let addr = "127.0.0.1:34567";
    // Create evaluator IO in background
    let (tx, rx) = channel();
    let c_eval = c.clone();
    thread::spawn(move || {
        let eval_io = NetIO::new(false, addr).unwrap();
        tx.send(eval_io).unwrap();
    });
    // Allow server to start slightly later
    thread::sleep(Duration::from_millis(50));
    let garbler_io = NetIO::new(true, addr).unwrap();
    let evaluator_io = rx.recv().unwrap();
    let bits = garble_and_eval(
        &c_eval,
        &[a],
        &[b],
        garbler_io,
        evaluator_io,
        &[sum_idx, carry_idx],
    );
    assert_eq!(bits, vec![a ^ b, a & b]);
}

#[test]
fn driver_handles_public_outputs() {
    // Circuit: out0 = a ^ b (public), out1 = a & b (secret)
    let mut c = Circuit::new();
    let a = c.fresh_wire();
    let b = c.fresh_wire();
    let xor_out = c.xor(a, b);
    let and_out = c.and(a, b);

    let (gio, eio) = MockIO::pair();
    let inputs_alice = [true];
    let inputs_bob = [false];
    let res = garble_and_eval_with_map(
        &c,
        emp_circuit::gc::input_map::InputMap::new(inputs_alice.len(), inputs_bob.len()),
        &inputs_alice,
        &inputs_bob,
        gio,
        eio,
        &[xor_out.id(), and_out.id()],
        &[(xor_out.id(), inputs_alice[0] ^ inputs_bob[0])],
    );
    assert_eq!(
        res.bits,
        vec![inputs_alice[0] ^ inputs_bob[0], inputs_alice[0] & inputs_bob[0]]
    );
}

#[test]
fn privacy_free_mock_io_random_inputs() {
    let (mut rng, trials) = (rand::rng(), 8);
    for _ in 0..trials {
        let (c, sum_idx, carry_idx) = build_1bit_adder();
        let a: bool = rng.random();
        let b: bool = rng.random();
        let (gio, eio) = MockIO::pair();
        let bits =
            garble_and_eval_privacy_free(&c, &[a], &[b], gio, eio, &[sum_idx, carry_idx]);
        assert_eq!(bits, vec![a ^ b, a & b]);
    }
}

#[test]
fn privacy_free_netio_loopback() {
    let (c, sum_idx, carry_idx) = build_1bit_adder();
    let a = true;
    let b = false;
    let addr = "127.0.0.1:34568";
    let (tx, rx) = channel();
    let c_eval = c.clone();
    thread::spawn(move || {
        let eval_io = NetIO::new(false, addr).unwrap();
        tx.send(eval_io).unwrap();
    });
    thread::sleep(Duration::from_millis(50));
    let garbler_io = NetIO::new(true, addr).unwrap();
    let evaluator_io = rx.recv().unwrap();
    let bits = garble_and_eval_privacy_free(
        &c_eval,
        &[a],
        &[b],
        garbler_io,
        evaluator_io,
        &[sum_idx, carry_idx],
    );
    assert_eq!(bits, vec![a ^ b, a & b]);
}

#[test]
fn privacy_free_public_wire_support() {
    // Circuit: out = a XOR public true, so output = !a
    let mut c = Circuit::new();
    let a = c.fresh_wire();
    let pub_one = c.public_wire(true);
    let out = c.xor(a, pub_one);

    let (gio, eio) = MockIO::pair();
    let bits = garble_and_eval_privacy_free(&c, &[false], &[], gio, eio, &[out.id()]);
    assert_eq!(bits, vec![true]);

    let (gio, eio) = MockIO::pair();
    let bits = garble_and_eval_privacy_free(&c, &[true], &[], gio, eio, &[out.id()]);
    assert_eq!(bits, vec![false]);
}

#[test]
fn privacy_free_multi_output_mock_io() {
    // Circuit: out0 = a & b, out1 = a ^ b
    let (mut rng, trials) = (rand::rng(), 4);
    for _ in 0..trials {
        let mut c = Circuit::new();
        let a = c.fresh_wire();
        let b = c.fresh_wire();
        let and_out = c.and(a, b);
        let xor_out = c.xor(a, b);
        let ai: bool = rng.random();
        let bi: bool = rng.random();
        let (gio, eio) = MockIO::pair();
        let bits = garble_and_eval_privacy_free(
            &c,
            &[ai],
            &[bi],
            gio,
            eio,
            &[and_out.id(), xor_out.id()],
        );
        assert_eq!(bits, vec![ai & bi, ai ^ bi]);
    }
}

#[test]
fn driver_public_wire_support() {
    // Circuit: out = a AND true_public, should equal a
    let mut c = Circuit::new();
    let a = c.fresh_wire();
    let pub_one = c.public_wire(true);
    let out = c.and(a, pub_one);

    let (gio, eio) = MockIO::pair();
    let bits = garble_and_eval(&c, &[false], &[], gio, eio, &[out.id()]);
    assert_eq!(bits, vec![false]);

    let (gio, eio) = MockIO::pair();
    let bits = garble_and_eval(&c, &[true], &[], gio, eio, &[out.id()]);
    assert_eq!(bits, vec![true]);
}
