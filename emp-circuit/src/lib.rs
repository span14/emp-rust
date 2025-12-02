#![deny(missing_docs)]

//! Circuit-building and garbling components layered on `emp-tool`.

pub mod bristol;
pub mod core;
pub mod gadgets;
pub mod gc;

pub use core::{
    circuit::Circuit,
    execution::{CircuitExecution, PlainEvaluator},
    gate::Gate,
    gate::GateKind,
    protocol::ProtocolExecution,
    protocol_runtime::{
        clear_executors,
        set_executors,
        CircuitExecution as RuntimeCircuitExecution,
        ProtocolExecution as RuntimeProtocolExecution,
        CIRC_EXEC,
        PROT_EXEC,
    },
    wire::Wire,
};
pub use gc::{
    driver::{
        garble_and_eval,
        garble_and_eval_privacy_free,
        garble_and_eval_privacy_free_with_map,
        garble_and_eval_with_map,
        DriverResult,
    },
    halfgate::{HalfGateEva, HalfGateGen},
    input_map::InputMap,
    label::{OutputDecoder, WireLabel},
    mock_io::MockIO,
    party::Party,
    protocol::{set_thread_local_evaluator, set_thread_local_garbler, set_thread_local_execs},
    privacy_free::{PrivacyFreeEvaluator, PrivacyFreeGarbler},
    garbler::HalfGateGarbler,
    evaluator::HalfGateEvaluator,
    ot::{InputOT, MockInputOTReceiver, MockInputOTSender},
};

#[cfg(feature = "ot-input")]
pub use gc::ot::IknpInputOT;
