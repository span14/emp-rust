/// Plain boolean matrix (column-major).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoolMatrix {
    rows: usize,
    cols: usize,
    data: Vec<bool>,
}

impl BoolMatrix {
    /// Create a zero matrix.
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![false; rows * cols],
        }
    }

    /// Create a column vector of length `len`.
    pub fn vector(len: usize) -> Self {
        Self::new(len, 1)
    }

    /// Construct from a flat column-major buffer.
    pub fn from_vec(rows: usize, cols: usize, data: Vec<bool>) -> Self {
        assert_eq!(rows * cols, data.len());
        Self { rows, cols, data }
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

    /// Transpose into a new matrix.
    pub fn transpose(&self) -> Self {
        let mut out = BoolMatrix::new(self.cols, self.rows);
        for i in 0..self.rows {
            for j in 0..self.cols {
                out.set(j, i, self.get(i, j));
            }
        }
        out
    }

    #[inline(always)]
    fn idx(&self, row: usize, col: usize) -> usize {
        col * self.rows + row
    }

    /// Get an entry.
    #[inline(always)]
    pub fn get(&self, row: usize, col: usize) -> bool {
        self.data[self.idx(row, col)]
    }

    /// Set an entry.
    #[inline(always)]
    pub fn set(&mut self, row: usize, col: usize, value: bool) {
        let idx = self.idx(row, col);
        self.data[idx] = value;
    }

    /// Compute `x[i] & y[j]` outer product.
    pub fn outer_product(x: &[bool], y: &[bool]) -> Self {
        let mut out = BoolMatrix::new(x.len(), y.len());
        for (i, &xb) in x.iter().enumerate() {
            for (j, &yb) in y.iter().enumerate() {
                out.set(i, j, xb & yb);
            }
        }
        out
    }

    /// Return a reference to the underlying column-major buffer.
    pub fn as_slice(&self) -> &[bool] {
        &self.data
    }
}
