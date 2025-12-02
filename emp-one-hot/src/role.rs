/// Party role in one-hot garbling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Garbler / generator.
    Generator,
    /// Evaluator.
    Evaluator,
}
