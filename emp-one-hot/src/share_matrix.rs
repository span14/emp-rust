use crate::{BoolMatrix, OneHotContext, Share};
use emp_tool::{Block, io_channel::IOChannel};
use std::ops::{Index, IndexMut};

/// Column-major matrix of shares.
#[derive(Clone, Debug)]
pub struct ShareMatrix {
    rows: usize,
    cols: usize,
    data: Vec<Share>,
}

impl ShareMatrix {
    /// Create an all-zero matrix.
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![Share::default(); rows * cols],
        }
    }

    /// Create a matrix of random wire labels.
    pub fn uniform<IO: IOChannel>(
        ctx: &mut OneHotContext<'_, IO>,
        rows: usize,
        cols: usize,
    ) -> Self {
        let mut out = ShareMatrix::new(rows, cols);
        for i in 0..rows {
            for j in 0..cols {
                out[(i, j)] = ctx.uniform_bit();
            }
        }
        out
    }

    /// Create a column vector.
    pub fn vector(len: usize) -> Self {
        Self::new(len, 1)
    }

    /// Build a constant matrix using the party's `bit` function.
    pub fn constant<IO: IOChannel>(ctx: &OneHotContext<'_, IO>, matrix: &BoolMatrix) -> Self {
        let mut out = ShareMatrix::new(matrix.rows(), matrix.cols());
        for i in 0..matrix.rows() {
            for j in 0..matrix.cols() {
                out[(i, j)] = ctx.bit(matrix.get(i, j));
            }
        }
        out
    }

    /// Number of rows.
    #[inline(always)]
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Number of columns.
    #[inline(always)]
    pub fn cols(&self) -> usize {
        self.cols
    }

    #[inline(always)]
    fn idx(&self, row: usize, col: usize) -> usize {
        col * self.rows + row
    }

    /// XOR a single cell.
    #[inline(always)]
    pub fn xor_cell(&mut self, row: usize, col: usize, share: Share) {
        let idx = self.idx(row, col);
        self.data[idx] ^= share;
    }

    /// XOR another matrix (same dimensions).
    pub fn xor_assign(&mut self, other: &ShareMatrix) {
        assert_eq!(self.rows, other.rows);
        assert_eq!(self.cols, other.cols);
        for (lhs, rhs) in self.data.iter_mut().zip(other.data.iter()) {
            *lhs ^= *rhs;
        }
    }

    /// XOR the transpose of `other` into this matrix.
    pub fn xor_transpose_assign(&mut self, other: &ShareMatrix) {
        assert_eq!(self.rows, other.cols);
        assert_eq!(self.cols, other.rows);
        for i in 0..self.rows {
            for j in 0..self.cols {
                self[(i, j)] ^= other[(j, i)];
            }
        }
    }

    /// Borrow the underlying vector for column vectors.
    pub fn as_slice(&self) -> &[Share] {
        assert_eq!(self.cols, 1);
        &self.data
    }

    /// Multiply a boolean matrix by a share vector (column-major).
    pub fn mul_bool_matrix(mat: &BoolMatrix, vec: &ShareMatrix) -> ShareMatrix {
        assert_eq!(mat.cols(), vec.rows());
        assert_eq!(vec.cols(), 1);
        let mut out = ShareMatrix::vector(mat.rows());
        for i in 0..mat.rows() {
            for j in 0..mat.cols() {
                if mat.get(i, j) {
                    out[i] ^= vec[(j, 0)];
                }
            }
        }
        out
    }

    /// Extract the color bits as a boolean matrix.
    pub fn colors(&self) -> BoolMatrix {
        let mut out = BoolMatrix::new(self.rows, self.cols);
        for i in 0..self.rows {
            for j in 0..self.cols {
                out.set(i, j, self[(i, j)].color());
            }
        }
        out
    }

    /// Return a transpose view as a new matrix.
    pub fn transpose(&self) -> ShareMatrix {
        let mut out = ShareMatrix::new(self.cols, self.rows);
        for i in 0..self.rows {
            for j in 0..self.cols {
                out[(j, i)] = self[(i, j)];
            }
        }
        out
    }

    /// Reveal the color bits of each entry.
    pub fn reveal<IO: IOChannel>(
        &mut self,
        ctx: &mut OneHotContext<'_, IO>,
    ) -> std::io::Result<()> {
        for share in &mut self.data {
            ctx.reveal(share)?;
        }
        Ok(())
    }
}

impl Index<(usize, usize)> for ShareMatrix {
    type Output = Share;

    #[inline(always)]
    fn index(&self, index: (usize, usize)) -> &Self::Output {
        let idx = self.idx(index.0, index.1);
        &self.data[idx]
    }
}

impl IndexMut<(usize, usize)> for ShareMatrix {
    #[inline(always)]
    fn index_mut(&mut self, index: (usize, usize)) -> &mut Self::Output {
        let idx = self.idx(index.0, index.1);
        &mut self.data[idx]
    }
}

impl Index<usize> for ShareMatrix {
    type Output = Share;

    #[inline(always)]
    fn index(&self, index: usize) -> &Self::Output {
        assert_eq!(self.cols, 1);
        &self.data[index]
    }
}

impl IndexMut<usize> for ShareMatrix {
    #[inline(always)]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        assert_eq!(self.cols, 1);
        &mut self.data[index]
    }
}

/// Decode generator/evaluator shares into a boolean matrix.
pub fn decode_matrix(delta: Block, generator: &ShareMatrix, evaluator: &ShareMatrix) -> BoolMatrix {
    assert_eq!(generator.rows(), evaluator.rows());
    assert_eq!(generator.cols(), evaluator.cols());
    let mut out = BoolMatrix::new(generator.rows(), generator.cols());
    for i in 0..out.rows() {
        for j in 0..out.cols() {
            let val = generator[(i, j)].0 ^ evaluator[(i, j)].0;
            if val == Block::ZERO {
                out.set(i, j, false);
            } else if val == delta {
                out.set(i, j, true);
            } else {
                panic!("invalid label during decode");
            }
        }
    }
    out
}
