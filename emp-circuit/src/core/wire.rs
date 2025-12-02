//! Wire labels used throughout the circuit representation.

/// A wire identifier with optional public value annotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Wire {
    id: usize,
    public: Option<bool>,
}

impl Wire {
    /// Create a private wire with the given identifier.
    pub fn new(id: usize) -> Self {
        Self { id, public: None }
    }

    /// Create a public wire with a fixed Boolean value.
    pub fn public(id: usize, value: bool) -> Self {
        Self {
            id,
            public: Some(value),
        }
    }

    /// Return the wire identifier.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Return the public value if present.
    pub fn public_value(&self) -> Option<bool> {
        self.public
    }
}
