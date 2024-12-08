use snarkvm_curves::{AffineCurve, PairingEngine, ProjectiveCurve};
use snarkvm_fields::Field;

use std::marker::PhantomData;

use std::fmt::Debug;

use super::{ExtFieldShare, FieldShare};
use super::{ProjectiveGroupShare, AffineGroupShare};


pub trait PairingShare<E: PairingEngine>:
    Clone + Copy + Debug + 'static + Send + Sync + PartialEq + Eq
{
    type FrShare: FieldShare<E::Fr>;
    type FqShare: FieldShare<E::Fq>;
    type FqeShare: ExtFieldShare<E::Fqe>;
    // TODO: wrong. Need to fix the PairingEngine interface though..
    type FqkShare: ExtFieldShare<E::Fqk>;
    //type FqkShare: GroupShare<MulFieldGroup<E::Fqk, E::Fr>, FieldShare = Self::FrShare>;
    type G1AffineShare: AffineGroupShare<E::G1Affine, FieldShare = Self::FrShare>;
    type G2AffineShare: AffineGroupShare<E::G2Affine, FieldShare = Self::FrShare>;
    type G1ProjectiveShare: ProjectiveGroupShare<E::G1Projective, FieldShare = Self::FrShare>;
    type G2ProjectiveShare: ProjectiveGroupShare<E::G2Projective, FieldShare = Self::FrShare>;
    type G1: AffProjShare<
        E::Fr,
        E::G1Affine,
        E::G1Projective,
        FrShare = Self::FrShare,
        AffineShare = Self::G1AffineShare,
        ProjectiveShare = Self::G1ProjectiveShare,
    >;
    type G2: AffProjShare<
        E::Fr,
        E::G2Affine,
        E::G2Projective,
        FrShare = Self::FrShare,
        AffineShare = Self::G2AffineShare,
        ProjectiveShare = Self::G2ProjectiveShare,
    >;
}

pub trait AffProjShare<
    Fr: Field,
    A: AffineCurve<ScalarField = Fr>,
    P: ProjectiveCurve<Affine = A>,
>
{
    type FrShare: FieldShare<Fr>;
    type AffineShare: AffineGroupShare<A, FieldShare = Self::FrShare>;
    type ProjectiveShare: ProjectiveGroupShare<P, FieldShare = Self::FrShare>;
    fn sh_aff_to_proj(g: Self::AffineShare) -> Self::ProjectiveShare;
    fn sh_proj_to_aff(g: Self::ProjectiveShare) -> Self::AffineShare;
    fn add_sh_proj_sh_aff(
        _a: Self::ProjectiveShare,
        _o: &Self::AffineShare,
    ) -> Self::ProjectiveShare {
        unimplemented!()
    }
    fn add_sh_proj_pub_aff(_a: Self::ProjectiveShare, _o: &A) -> Self::ProjectiveShare {
        unimplemented!()
    }
    fn add_pub_proj_sh_aff(_a: &P, _o: Self::AffineShare) -> Self::ProjectiveShare {
        unimplemented!()
    }
}
