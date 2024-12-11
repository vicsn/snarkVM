use super::Field;

use std::borrow::Cow;
use std::collections::BTreeMap;

/// Represents either a sparse polynomial or a dense one.
/// This stub is here so we can implement custom polynomial division for specific field types. 
#[derive(Clone, Debug)]
pub enum Polynomial<'a, F: Field> {
    /// Represents the case where `self` is a sparse polynomial
    SPolynomial(Cow<'a, SparsePolynomial<F>>),
    /// Represents the case where `self` is a dense polynomial
    DPolynomial(Cow<'a, DensePolynomial<F>>),
}

/// Stores a polynomial in coefficient form.
#[derive(Clone, Default, Debug)]
pub struct DensePolynomial<F: Field> {
    /// The coefficient of `x^i` is stored at location `i` in `self.coeffs`.
    pub coeffs: Vec<F>,
}

/// Stores a sparse polynomial in coefficient form.
#[derive(Clone, Default, Debug)]
pub struct SparsePolynomial<F: Field> {
    /// The coefficient a_i of `x^i` is stored as (i, a_i) in `self.coeffs`.
    /// the entries in `self.coeffs` *must*  be sorted in increasing order of
    /// `i`.
    pub coeffs: BTreeMap<usize, F>,
}

/// New Polynomial types used for MPC operations.
pub type MpcDensePolynomial<T> = Vec<T>;
pub type MpcSparsePolynomial<T> = BTreeMap<usize, T>;
pub type DenseOrSparsePolynomial<T> = Result<MpcDensePolynomial<T>, MpcSparsePolynomial<T>>;
