//! High-level circuit driver to garble and evaluate a circuit over an IO channel.

use crate::core::circuit::Circuit;
use crate::gc::{
    evaluator::HalfGateEvaluator, garbler::HalfGateGarbler, input_map::InputMap, party::Party,
};
use crate::gc::privacy_free::{PrivacyFreeEvaluator, PrivacyFreeGarbler};
use emp_tool::IOChannel;
use std::collections::HashMap;

/// Result of a driver run, exposing decoded bits and the decoder used.
pub struct DriverResult {
    /// Decoded output bits (ordered as requested).
    pub bits: Vec<bool>,
    /// Decoder that was used on the garbler side (secret outputs only).
    pub decoder: crate::gc::label::OutputDecoder,
}

/// Run a full garble-and-evaluate pipeline over a single IO channel.
///
/// - `inputs_alice`: garbler-owned inputs as booleans.
/// - `inputs_bob`: evaluator-owned inputs as booleans.
/// - `output_indices`: indices of wires to reveal.
pub fn garble_and_eval<IOG, IOE>(
    circuit: &Circuit,
    inputs_alice: &[bool],
    inputs_bob: &[bool],
    garbler_io: IOG,
    evaluator_io: IOE,
    output_indices: &[usize],
) -> Vec<bool>
where
    IOG: IOChannel + Send + 'static,
    IOE: IOChannel + Send + 'static,
{
    garble_and_eval_with_map(
        circuit,
        InputMap::new(inputs_alice.len(), inputs_bob.len()),
        inputs_alice,
        inputs_bob,
        garbler_io,
        evaluator_io,
        output_indices,
        &[],
    )
    .bits
}

/// Garble and evaluate a circuit with explicit input mapping and public-output hints.
///
/// `public_outputs` allows the caller to mark certain output wire indices as public with their
/// known Boolean value; these will be returned directly without requiring evaluator round-trips.
pub fn garble_and_eval_with_map<IOG, IOE>(
    circuit: &Circuit,
    input_map: InputMap,
    inputs_alice: &[bool],
    inputs_bob: &[bool],
    garbler_io: IOG,
    evaluator_io: IOE,
    output_indices: &[usize],
    public_outputs: &[(usize, bool)],
) -> DriverResult
where
    IOG: IOChannel + Send + 'static,
    IOE: IOChannel + Send + 'static,
{
    let wire_count = circuit.wire_count();
    let public_map: HashMap<usize, bool> = public_outputs.iter().copied().collect();
    let secret_outputs: Vec<usize> = output_indices
        .iter()
        .copied()
        .filter(|idx| !public_map.contains_key(idx))
        .collect();

    // Spawn garbler
    let circ_g = circuit.clone();
    let inputs_alice_vec = inputs_alice.to_vec();
    let inputs_bob_vec = inputs_bob.to_vec();
    let secret_outputs_g = secret_outputs.clone();
    let output_indices_vec = output_indices.to_vec();
    let public_map_g = public_map.clone();
    let input_map_g = input_map.clone();
    let garbler_handle = std::thread::spawn(move || {
        let mut garbler = HalfGateGarbler::new(garbler_io, wire_count);
        let alice_indices = input_map_g.indices(Party::Garbler);
        let bob_indices = input_map_g.indices(Party::Evaluator);

        // Assign garbler inputs (local only), then ship them explicitly.
        garbler.feed(Party::Garbler, &alice_indices, &inputs_alice_vec);
        garbler.send_garbler_inputs(&alice_indices, &inputs_alice_vec);
        // Assign evaluator inputs and send their labels.
        garbler.feed(Party::Evaluator, &bob_indices, &inputs_bob_vec);

        // Garble circuit
        garbler.garble(&circ_g);
        // Prepare decoder and outputs for secret wires only
        garbler.set_outputs(&secret_outputs_g);
        let decoder = garbler.decoder().clone();
        // Reveal bits from evaluator for secret outputs
        let revealed = garbler.reveal(&secret_outputs_g);

        // Merge public and secret outputs in caller-specified order.
        let mut bits = Vec::with_capacity(output_indices_vec.len());
        let mut secret_iter = revealed.into_iter();
        for idx in output_indices_vec {
            if let Some(val) = public_map_g.get(&idx) {
                bits.push(*val);
            } else {
                bits.push(secret_iter.next().expect("missing secret output bit"));
            }
        }
        DriverResult { bits, decoder }
    });

    // Evaluator side
    let circ_e = circuit.clone();
    let secret_outputs_e = secret_outputs;
    let input_map_e = input_map;
    let evaluator_handle = std::thread::spawn(move || {
        let mut evaluator = HalfGateEvaluator::new(evaluator_io);
        // Receive garbler-owned labels explicitly, then evaluator-owned labels.
        let alice_indices = input_map_e.indices(Party::Garbler);
        let bob_indices = input_map_e.indices(Party::Evaluator);
        evaluator.receive_garbler_inputs(&alice_indices);
        evaluator.feed(Party::Evaluator, &bob_indices);
        evaluator.evaluate(&circ_e);
        // Send only secret outputs back to garbler
        evaluator.send_outputs(&secret_outputs_e);
    });

    let res = garbler_handle.join().unwrap();
    evaluator_handle.join().unwrap();
    res
}

/// Privacy-free variant of `garble_and_eval` with default mapping.
pub fn garble_and_eval_privacy_free<IOG, IOE>(
    circuit: &Circuit,
    inputs_alice: &[bool],
    inputs_bob: &[bool],
    garbler_io: IOG,
    evaluator_io: IOE,
    output_indices: &[usize],
) -> Vec<bool>
where
    IOG: IOChannel + Send + 'static,
    IOE: IOChannel + Send + 'static,
{
    garble_and_eval_privacy_free_with_map(
        circuit,
        InputMap::new(inputs_alice.len(), inputs_bob.len()),
        inputs_alice,
        inputs_bob,
        garbler_io,
        evaluator_io,
        output_indices,
        &[],
    )
    .bits
}

/// Privacy-free variant with explicit input mapping and public-output hints.
pub fn garble_and_eval_privacy_free_with_map<IOG, IOE>(
    circuit: &Circuit,
    input_map: InputMap,
    inputs_alice: &[bool],
    inputs_bob: &[bool],
    garbler_io: IOG,
    evaluator_io: IOE,
    output_indices: &[usize],
    public_outputs: &[(usize, bool)],
) -> DriverResult
where
    IOG: IOChannel + Send + 'static,
    IOE: IOChannel + Send + 'static,
{
    let wire_count = circuit.wire_count();
    let public_map: HashMap<usize, bool> = public_outputs.iter().copied().collect();
    let secret_outputs: Vec<usize> = output_indices
        .iter()
        .copied()
        .filter(|idx| !public_map.contains_key(idx))
        .collect();

    // Spawn garbler
    let circ_g = circuit.clone();
    let inputs_alice_vec = inputs_alice.to_vec();
    let inputs_bob_vec = inputs_bob.to_vec();
    let secret_outputs_g = secret_outputs.clone();
    let output_indices_vec = output_indices.to_vec();
    let public_map_g = public_map.clone();
    let input_map_g = input_map.clone();
    let garbler_handle = std::thread::spawn(move || {
        let mut garbler = PrivacyFreeGarbler::new(garbler_io, wire_count);
        let alice_indices = input_map_g.indices(Party::Garbler);
        let bob_indices = input_map_g.indices(Party::Evaluator);

        garbler.feed(Party::Garbler, &alice_indices, &inputs_alice_vec);
        garbler.send_garbler_inputs(&alice_indices, &inputs_alice_vec);
        garbler.feed(Party::Evaluator, &bob_indices, &inputs_bob_vec);

        garbler.garble(&circ_g);
        garbler.set_outputs(&secret_outputs_g);
        let decoder = garbler.decoder().clone();
        let revealed = garbler.reveal(&secret_outputs_g);

        let mut bits = Vec::with_capacity(output_indices_vec.len());
        let mut secret_iter = revealed.into_iter();
        for idx in output_indices_vec {
            if let Some(val) = public_map_g.get(&idx) {
                bits.push(*val);
            } else {
                bits.push(secret_iter.next().expect("missing secret output bit"));
            }
        }
        DriverResult { bits, decoder }
    });

    // Evaluator side
    let circ_e = circuit.clone();
    let secret_outputs_e = secret_outputs;
    let input_map_e = input_map;
    let evaluator_handle = std::thread::spawn(move || {
        let mut evaluator = PrivacyFreeEvaluator::new(evaluator_io);
        let alice_indices = input_map_e.indices(Party::Garbler);
        let bob_indices = input_map_e.indices(Party::Evaluator);
        evaluator.receive_garbler_inputs(&alice_indices);
        evaluator.feed(Party::Evaluator, &bob_indices);
        evaluator.evaluate(&circ_e);
        evaluator.send_outputs(&secret_outputs_e);
    });

    let res = garbler_handle.join().unwrap();
    evaluator_handle.join().unwrap();
    res
}
