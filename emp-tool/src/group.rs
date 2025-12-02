//! Elliptic-curve group utilities modeled after the C++ `group.h` wrappers.
//!
//! This implementation uses the NIST P-256 curve via the `p256` crate.

use p256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField,
    },
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
};

/// Big integer wrapper (scalar modulo curve order).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigInt(pub Scalar);

impl BigInt {
    /// Create zero.
    pub fn zero() -> Self {
        BigInt(Scalar::ZERO)
    }

    /// Return size in bytes when serialized.
    pub fn size(&self) -> usize {
        32
    }

    /// Serialize to big-endian bytes.
    pub fn to_bin(&self, out: &mut [u8]) {
        let bytes = self.0.to_bytes();
        out[..32].copy_from_slice(bytes.as_slice());
    }

    /// Deserialize from big-endian bytes (clamped to field size).
    pub fn from_bin(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; 32] = bytes.try_into().ok()?;
        let sc = Scalar::from_repr(arr.into());
        if bool::from(sc.is_some()) {
            Some(BigInt(sc.unwrap()))
        } else {
            None
        }
    }

    /// Add two scalars modulo curve order.
    pub fn add(&self, rhs: &BigInt) -> BigInt {
        BigInt(self.0 + rhs.0)
    }

    /// Multiply two scalars modulo curve order.
    pub fn mul(&self, rhs: &BigInt) -> BigInt {
        BigInt(self.0 * rhs.0)
    }

    /// Alias for scalar addition.
    pub fn add_mod(&self, rhs: &BigInt) -> BigInt {
        self.add(rhs)
    }

    /// Alias for scalar multiplication.
    pub fn mul_mod(&self, rhs: &BigInt) -> BigInt {
        self.mul(rhs)
    }
}

/// Curve group wrapper.
pub struct Group {
    generator: AffinePoint,
}

impl Group {
    /// Instantiate the P-256 group wrapper.
    pub fn new() -> Self {
        Group {
            generator: AffinePoint::GENERATOR,
        }
    }

    /// Return the standard generator.
    pub fn get_generator(&self) -> Point {
        Point {
            point: ProjectivePoint::from(self.generator),
        }
    }

    /// Multiply the generator by a scalar.
    pub fn mul_gen(&self, m: &BigInt) -> Point {
        Point {
            point: self.generator * m.0,
        }
    }
}

/// Point on the curve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    point: ProjectivePoint,
}

impl Point {
    /// Encode to compressed SEC1 form.
    pub fn to_bin(&self) -> EncodedPoint {
        AffinePoint::from(self.point).to_encoded_point(true)
    }

    /// Length of the encoded point.
    pub fn size(&self) -> usize {
        self.to_bin().len()
    }

    /// Decode from SEC1 bytes.
    pub fn from_bin(bytes: &[u8]) -> Option<Self> {
        let enc = EncodedPoint::from_bytes(bytes).ok()?;
        let affine = AffinePoint::from_encoded_point(&enc);
        if bool::from(affine.is_some()) {
            Some(Point {
                point: ProjectivePoint::from(affine.unwrap()),
            })
        } else {
            None
        }
    }

    /// Add two points.
    pub fn add(&self, rhs: &Point) -> Point {
        Point {
            point: self.point + rhs.point,
        }
    }

    /// Multiply by a scalar.
    pub fn mul(&self, m: &BigInt) -> Point {
        Point {
            point: self.point * m.0,
        }
    }

    /// Invert the point.
    pub fn inv(&self) -> Point {
        Point { point: -self.point }
    }

    /// Equality check helper.
    pub fn equals(&self, other: &Point) -> bool {
        self == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn point_roundtrip() {
        let g = Group::new();
        let p = g.get_generator();
        let bin = p.to_bin();
        let q = Point::from_bin(bin.as_bytes()).unwrap();
        assert!(p.equals(&q));
    }

    #[test]
    fn scalar_mul_and_inv() {
        let g = Group::new();
        let scalar = BigInt(Scalar::from(5u64));
        let p = g.mul_gen(&scalar);
        let minus = p.inv();
        let neutral = p.add(&minus);
        let id = ProjectivePoint::IDENTITY;
        assert_eq!(neutral.point, id);
    }
}
