use digest::Digest;
use rand::Rng;
use sha2;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use snarkvm_utilities::{CanonicalSerialize, Compress, FromBits, ToBits};
use snarkvm_fields::{FftField, PrimeField};
use snarkvm_fields::MpcWire;

use crate::channel;
use crate::MpcField;
use crate::{Reveal, FieldShare};
use mpc_net::two as net_two;

/// Vector-Commitable Field
pub trait ComField: FftField + MpcWire {
    type Commitment: CanonicalSerialize;
    type Key;
    type OpeningProof: CanonicalSerialize;
    fn public_rand<R: Rng>(r: &mut R) -> Self;
    fn commit(vs: &[Self]) -> (Self::Key, Self::Commitment);
    fn open_at(vs: &[Self], key: &Self::Key, i: usize) -> (Self, Self::OpeningProof);
    fn check_opening(c: &Self::Commitment, p: Self::OpeningProof, i: usize, v: Self) -> bool;
}

// Custom required trait implementations
impl<'de, Fr: PrimeField, S: FieldShare<Fr>> Deserialize<'de> for MpcField<Fr, S> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        unimplemented!()
    }
}

impl<Fr: PrimeField, S: FieldShare<Fr>> Serialize for MpcField<Fr, S> {
    fn serialize<SS: Serializer>(&self, serializer: SS) -> Result<SS::Ok, SS::Error> {
        unimplemented!()
    }
}

impl<Fr: PrimeField, S: FieldShare<Fr>> ToBits for MpcField<Fr, S> {
    fn num_bits() -> Option<usize> {
        unimplemented!()
    }
    fn to_bits_be(&self) -> Vec<bool> {
        unimplemented!()
    }
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        unimplemented!()
    }
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        unimplemented!()
    }
}

impl<Fr: PrimeField, S: FieldShare<Fr>> FromBits for MpcField<Fr, S> {
    fn from_bits_be(_bits: &[bool]) -> anyhow::Result<Self> {
        unimplemented!()
    }
    fn from_bits_le(_bits: &[bool]) -> anyhow::Result<Self> {
        unimplemented!()
    }
}


// End of custom required trait implementations

impl<Fr: PrimeField, S: FieldShare<Fr>> ComField for MpcField<Fr, S> {
    type Commitment = (Vec<u8>, Vec<u8>);
    type Key = Vec<Vec<Vec<u8>>>;
    type OpeningProof = (
        Fr,
        Fr,
        Vec<(Vec<u8>, Vec<u8>)>,
    );
    fn public_rand<R: Rng>(r: &mut R) -> Self {
        Self::from_public(Fr::rand(r))
    }
    fn commit(vs: &[Self]) -> (Self::Key, Self::Commitment) {
        let mut tree = Vec::new();
        let mut hashes: Vec<Vec<u8>> = vs
            .into_iter()
            .enumerate()
            .map(|(_i, v)| {
                let mut bytes_out = Vec::new();
                v.unwrap_as_public().serialize_with_mode(&mut bytes_out, Compress::No).unwrap();
                let o = sha2::Sha256::digest(&bytes_out[..]).as_slice().to_owned();
                o
            })
            .collect();
        assert!(hashes.len().is_power_of_two());
        while hashes.len() > 1 {
            let n = hashes.len() / 2;
            let mut new = Vec::new();
            for i in 0..n {
                let mut h = sha2::Sha256::default();
                h.update(&hashes[2 * i]);
                h.update(&hashes[2 * i + 1]);
                new.push(h.finalize().as_slice().to_owned());
            }
            tree.push(std::mem::replace(&mut hashes, new));
        }
        let slf = hashes.pop().unwrap();
        let other = net_two::exchange_bytes(&slf).unwrap();
        if net_two::am_first() {
            (tree, (other, slf))
        } else {
            (tree, (slf, other))
        }
    }
    fn open_at(inputs: &[Self], tree: &Self::Key, mut i: usize) -> (Self, Self::OpeningProof) {
        let self_f = inputs[i].unwrap_as_public();
        let other_f = channel::exchange(&self_f);
        let mut siblings = Vec::new();
        for level in 0..tree.len() {
            siblings.push(tree[level][i ^ 1].clone());
            i /= 2;
        }
        assert_eq!(i / 2, 0);
        let other: Vec<_> = siblings
            .iter()
            .map(|s| net_two::exchange_bytes(s).unwrap())
            .collect();
        let p = if net_two::am_first() {
            siblings.into_iter().zip(other.into_iter()).collect()
        } else {
            other.into_iter().zip(siblings.into_iter()).collect()
        };
        (
            MpcField::from_public(self_f + other_f),
            if net_two::am_first() {
                (self_f, other_f, p)
            } else {
                (other_f, self_f, p)
            },
        )
    }
    fn check_opening(c: &Self::Commitment, p: Self::OpeningProof, i: usize, v: Self) -> bool {
        if p.0 + p.1 != v.reveal() {
            return false;
        }
        let mut hash0 = Vec::new();
        p.0.serialize_with_mode(&mut hash0, Compress::No).unwrap();
        hash0 = sha2::Sha256::digest(&hash0).as_slice().to_owned();
        let mut hash1 = Vec::new();
        p.1.serialize_with_mode(&mut hash1, Compress::No).unwrap();
        hash1 = sha2::Sha256::digest(&hash1).as_slice().to_owned();
        for (j, (sib0, sib1)) in p.2.into_iter().enumerate() {
            let mut h0 = sha2::Sha256::default();
            let mut h1 = sha2::Sha256::default();
            if (i >> j) & 1 == 0 {
                h0.update(&hash0);
                h0.update(&sib0);
                h1.update(&hash1);
                h1.update(&sib1);
            } else {
                h0.update(&sib0);
                h0.update(&hash0);
                h1.update(&sib1);
                h1.update(&hash1);
            }
            hash0 = h0.finalize().as_slice().to_owned();
            hash1 = h1.finalize().as_slice().to_owned();
        }
        &(hash1, hash0) == c
    }
}
