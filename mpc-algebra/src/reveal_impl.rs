
use crate::{struct_reveal_simp_impl, Reveal, MpcField, FieldShare};
use snarkvm_fft::{EvaluationDomain, domain::{IFFTPrecomputation, FFTPrecomputation}};
use snarkvm_fields::PrimeField;

impl<F: PrimeField, S: FieldShare<F>> Reveal for EvaluationDomain<MpcField<F, S>>
{
    type Base = EvaluationDomain<F>;
    struct_reveal_simp_impl!(EvaluationDomain; size, log_size_of_group, size_as_field_element, size_inv, group_gen, group_gen_inv, generator_inv);
}
impl<F: PrimeField, S: FieldShare<F>> Reveal for FFTPrecomputation<MpcField<F, S>>
{
    type Base = FFTPrecomputation<F>;
    struct_reveal_simp_impl!(FFTPrecomputation; roots, domain);
}
impl<F: PrimeField, S: FieldShare<F>> Reveal for IFFTPrecomputation<MpcField<F, S>>
{
    type Base = IFFTPrecomputation<F>;
    struct_reveal_simp_impl!(IFFTPrecomputation; inverse_roots, domain);
}

// impl<E: Field> MpcWire for LabeledPolynomial<E, DensePolynomial<E>> {
//     fn publicize(&mut self) {
//         let mut p = (*self.polynomial).clone();
//         p.publicize();
//         self.polynomial = Rc::new(p);
//     }
//     fn is_shared(&self) -> bool {
//         self.polynomial.is_shared()
//     }
// }

// impl<C: PCCommitment + MpcWire> MpcWire for LabeledCommitment<C> {
//     struct_mpc_wire_simp_impl!(LabeledCommitment; commitment);
// }

// impl<C: PairingEngine> MpcWire for Commitment<C> {
//     struct_mpc_wire_simp_impl!(Commitment; comm, shifted_comm);
// }

// impl<C: PairingEngine> MpcWire for kzg10::Commitment<C> {
//     struct_mpc_wire_simp_impl!(kzg10::Commitment; 0);
// }
