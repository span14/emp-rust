//! Party identifiers used when assigning inputs.
/// The two GC parties.
pub enum Party {
    /// Garbler (ALICE).
    Garbler = 1,
    /// Evaluator (BOB).
    Evaluator = 2,
}
