use snarkvm_curves::msm::batched::msm;
use derivative::Derivative;
use snarkvm_curves::{AffineCurve, ProjectiveCurve};
use std::marker::PhantomData;

/// Multi-scalar multiplications
pub trait Msm<G, S>: Send + Sync + 'static {
    fn msm(bases: &[G], scalars: &[S]) -> G;
    fn pre_reveal_check() {}
}

// #[derive(Debug, Derivative)]
// #[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
// pub struct NaiveMsm<G>(pub PhantomData<G>);

// impl<G> Msm<G, G::ScalarField> for NaiveMsm<G> {
//     fn msm(bases: &[G], scalars: &[G::ScalarField]) -> G {
//         bases
//             .iter()
//             .zip(scalars.iter())
//             .map(|(b, s)| {
//                 let mut b = b.clone();
//                 b *= *s;
//                 b
//             })
//             .fold(G::zero(), |a, b| a + b)
//     }
// }

#[derive(Debug, Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct AffineMsm<G: AffineCurve>(pub PhantomData<G>);

impl<G: AffineCurve> Msm<G, G::ScalarField> for AffineMsm<G> {
    fn msm(bases: &[G], scalars: &[G::ScalarField]) -> G {
        let scalars: Vec<_> = scalars.iter().map(|&s| s.into()).collect();
        msm(&bases, &scalars).into()
    }
}

#[derive(Debug, Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct ProjectiveMsm<G: ProjectiveCurve>(pub PhantomData<G>);

impl<G: ProjectiveCurve> Msm<G, G::ScalarField> for ProjectiveMsm<G> {
    fn msm(bases: &[G], scalars: &[G::ScalarField]) -> G {
        let bases: Vec<G::Affine> = bases.iter().map(|&s| s.into()).collect();
        let scalars: Vec<_> = scalars.iter().map(|&s| s.into()).collect();
        msm(&bases, &scalars)
    }
}
