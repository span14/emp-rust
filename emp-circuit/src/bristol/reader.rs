//! Bristol fashion circuit parser.

use crate::core::{circuit::Circuit, gate::Gate, wire::Wire};

/// Summary of a parsed Bristol circuit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BristolCircuit {
    /// Number of gates.
    pub gates: usize,
    /// Number of wires.
    pub wires: usize,
    /// Input counts per party (if present).
    pub inputs: Vec<usize>,
    /// Output counts per party (if present).
    pub outputs: Vec<usize>,
}

/// Parse a Bristol-formatted string into a `Circuit` and metadata.
pub fn parse_str(contents: &str) -> Option<(Circuit, BristolCircuit)> {
    let mut lines = contents.lines().peekable();
    let header = lines.next()?;
    let mut it = header.split_whitespace();
    let gates: usize = it.next()?.parse().ok()?;
    let wires: usize = it.next()?.parse().ok()?;

    // Optional counts line: num_parties, then inputs, then outputs.
    let mut meta = BristolCircuit {
        gates,
        wires,
        inputs: Vec::new(),
        outputs: Vec::new(),
    };
    if let Some(peek) = lines.peek().cloned() {
        let tokens: Vec<&str> = peek.split_whitespace().collect();
        if let Some(np_tok) = tokens.get(0) {
            if let Ok(np) = np_tok.parse::<usize>() {
                if tokens.len() >= 1 + np + 1 {
                    let mut inputs = Vec::with_capacity(np);
                    let mut idx = 1;
                    for _ in 0..np {
                        inputs.push(tokens.get(idx)?.parse().ok()?);
                        idx += 1;
                    }
                    let outputs: Vec<usize> = tokens[idx..]
                        .iter()
                        .filter_map(|t| t.parse().ok())
                        .collect();
                    if outputs.len() == tokens.len() - idx {
                        meta.inputs = inputs;
                        meta.outputs = outputs;
                        lines.next();
                    }
                }
            }
        }
    }

    let mut circ = Circuit::new();
    // Pre-allocate wires up to reported count.
    for _ in 0..meta.wires {
        circ.fresh_wire();
    }

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let num_in: usize = parts.next()?.parse().ok()?;
        let num_out: usize = parts.next()?.parse().ok()?;
        let mut ins = Vec::with_capacity(num_in);
        for _ in 0..num_in {
            let idx: usize = parts.next()?.parse().ok()?;
            ins.push(Wire::new(idx));
        }
        let outs_idx: usize = parts.next()?.parse().ok()?;
        let gate_type = parts.next()?;
        let gate = match (gate_type, num_in, num_out) {
            ("XOR", 2, 1) => Gate::xor(ins[0], ins[1], Wire::new(outs_idx)),
            ("AND", 2, 1) => Gate::and(ins[0], ins[1], Wire::new(outs_idx)),
            ("INV", 1, 1) => Gate::not(ins[0], Wire::new(outs_idx)),
            _ => return None,
        };
        circ.push_gate(gate);
    }

    Some((circ, meta))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::execution::PlainEvaluator;

    #[test]
    fn parse_header() {
        let txt = "3 5\n2 1 0 1 2 XOR\n2 1 2 3 4 AND\n1 1 4 0 INV";
        let (c, meta) = parse_str(txt).unwrap();
        assert_eq!(meta.gates, 3);
        assert_eq!(meta.wires, 5);
        let mut ev = PlainEvaluator::new();
        let vals = ev.evaluate(&c, &[true, false, true, false, false]);
        let last = c.gates().last().unwrap().output().id();
        assert_eq!(vals.get(&last), Some(&true));
    }
}
