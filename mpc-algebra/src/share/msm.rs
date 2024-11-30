use derivative::Derivative;
use snarkvm_curves::{AffineCurve, ProjectiveCurve};
use snarkvm_console::prelude::{GroupTrait, ScalarTrait};
use std::marker::PhantomData;

/// Multi-scalar multiplications
pub trait Msm<G, S>: Send + Sync + 'static {
    fn msm(bases: &[G], scalars: &[S]) -> G;
    fn pre_reveal_check() {}
}

#[derive(Debug, Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct NaiveMsm<C: ScalarTrait, G: GroupTrait<C>>(pub PhantomData<G>);

impl<C: ScalarTrait, G: GroupTrait<C>> Msm<G, C> for NaiveMsm<G> {
    fn msm(bases: &[G], scalars: &[C]) -> G {
        bases
            .iter()
            .zip(scalars.iter())
            .map(|(b, s)| {
                let mut b = b.clone();
                b *= *s;
                b
            })
            .fold(G::zero(), |a, b| a + b)
    }
}

#[derive(Debug, Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct AffineMsm<G: AffineCurve>(pub PhantomData<G>);

impl<C: ScalarTrait, G: AffineCurve> Msm<G, C> for AffineMsm<G> {
    fn msm(bases: &[G], scalars: &[C]) -> G {
        G::multi_scalar_mul(bases, scalars).into()
    }
}

#[derive(Debug, Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct ProjectiveMsm<G: ProjectiveCurve>(pub PhantomData<G>);

impl<C: ScalarTrait, G: ProjectiveCurve> Msm<G, C> for ProjectiveMsm<G> {
    fn msm(bases: &[G], scalars: &[C]) -> G {
        bases[0].clone()
        // TODO: implement this method.
        // let bases: Vec<G::Affine> = bases.iter().map(|s| s.clone().into()).collect();
        // <G::Affine as AffineCurve>::multi_scalar_mul(&bases, scalars)
    }
}
