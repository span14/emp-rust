//! Rust re-implementation of EMP OT protocols.
//!
//! Currently implemented:
//! - Naor–Pinkas base OT over Ristretto (`np::NaorPinkas`).
//! - IKNP OT extension (`iknp::{IknpSender, IknpReceiver}`).
//! - Chou–Orlandi base OT over Ristretto (`co::ChouOrlandi`).
//! - Correlated and random OT wrappers (`cot::{CotSender, CotReceiver}`).
//! - Ferret scaffolding (constants/LPN placeholders) (`ferret::*`).

pub mod base;
pub mod channel;
pub mod co;
pub mod cot;
pub mod ferret;
pub mod iknp;
pub mod np;

pub use base::{BaseOtRecv, BaseOtSend, NaorPinkasBase};
pub use channel::Channel;
pub use co::ChouOrlandi;
pub use cot::{CotReceiver, CotSender};
pub use iknp::{IknpReceiver, IknpSender};
pub use np::NaorPinkas;
