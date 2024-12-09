use snarkvm_fields::{PrimeField, FftParameters};
use snarkvm_fields::FieldParameters;
use snarkvm_fields::{PoseidonDefaultParameters, PoseidonDefaultParametersEntry};
use snarkvm_utilities::biginteger::{BigInteger as _BigInteger};
use std::default::Default;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;

use crate::FieldShare;
use crate::MpcBigInteger;

pub trait MpcFpParameters<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: _BigInteger>: FieldParameters<BigInteger = MpcBigInteger<F, S, T>> {}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MpcFrParameters<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: _BigInteger> {
    pub _marker: PhantomData<(F, S, T)>
}

impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: _BigInteger> MpcFpParameters<F, S, T> for MpcFrParameters<F, S, T> {}

// Copy of bls12_377::FrParameters
// TODO: consider BigInteger = T  
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: _BigInteger + 'static> FftParameters for MpcFrParameters<F, S, T> {
    type BigInteger = MpcBigInteger<F, S, T>;

    #[rustfmt::skip]
    fn POWERS_OF_ROOTS_OF_UNITY() -> Vec<Self::BigInteger> {
        let powers = <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY();
        powers.into_iter().map(|power| {
            MpcBigInteger::<F, S, T>{val: power, _marker: PhantomData}
        }).collect()

        // MpcBigInteger::<F, S, T>{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[0], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[1], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[2], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[3], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[4], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[5], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[6], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[7], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[8], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[9], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[10], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[11], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[12], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[13], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[14], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[15], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[16], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[17], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[18], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[19], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[20], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[31], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[32], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[33], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[34], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[35], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[36], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[37], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[38], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[39], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[40], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[41], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[42], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[43], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[44], _marker: PhantomData},
    //     Self::BigInteger{val: <<F as PrimeField>::Parameters as FftParameters>::POWERS_OF_ROOTS_OF_UNITY[45], _marker: PhantomData},
    }

    #[rustfmt::skip]
    const TWO_ADICITY: u32 = 47;
    /// TWO_ADIC_ROOT_OF_UNITY = 8065159656716812877374967518403273466521432693661810619979959746626482506078
    /// Encoded in Montgomery form, the value is
    /// (8065159656716812877374967518403273466521432693661810619979959746626482506078 * R % q) =
    /// 7039866554349711480672062101017509031917008525101396696252683426045173093960
    #[rustfmt::skip]
    const TWO_ADIC_ROOT_OF_UNITY: MpcBigInteger<F, S, T> = MpcBigInteger::<F, S, T>{
        val: <<F as PrimeField>::Parameters as FftParameters>::TWO_ADIC_ROOT_OF_UNITY,
        _marker: PhantomData, 
    };
}

// Copy of bls12_377::FrParameters
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: _BigInteger> FieldParameters for MpcFrParameters<F, S, T> {
    #[rustfmt::skip]
    const CAPACITY: u32 = Self::MODULUS_BITS - 1;
    /// GENERATOR = 22
    /// Encoded in Montgomery form, so the value is
    /// (22 * R) % q = 5642976643016801619665363617888466827793962762719196659561577942948671127251
    #[rustfmt::skip]
    const GENERATOR: MpcBigInteger<F, S, T> = MpcBigInteger::<F, S, T>{
        val: <<F as PrimeField>::Parameters as FieldParameters>::GENERATOR,
        _marker: PhantomData, 
    };
    #[rustfmt::skip]
    const INV: u64 = 725501752471715839u64;
    /// MODULUS = 8444461749428370424248824938781546531375899335154063827935233455917409239041
    #[rustfmt::skip]
    const MODULUS: MpcBigInteger<F, S, T> = MpcBigInteger::<F, S, T>{
        val: <<F as PrimeField>::Parameters as FieldParameters>::MODULUS,
        _marker: PhantomData, 
    };
    #[rustfmt::skip]
    const MODULUS_BITS: u32 = 253;
    /// (r - 1)/2 =
    /// 4222230874714185212124412469390773265687949667577031913967616727958704619520
    #[rustfmt::skip]
    const MODULUS_MINUS_ONE_DIV_TWO: MpcBigInteger<F, S, T> = MpcBigInteger::<F, S, T>{
        val: <<F as PrimeField>::Parameters as FieldParameters>::MODULUS_MINUS_ONE_DIV_TWO,
        _marker: PhantomData, 
    };
    #[rustfmt::skip]
    const R: MpcBigInteger<F, S, T> = MpcBigInteger::<F, S, T>{
        val: <<F as PrimeField>::Parameters as FieldParameters>::R,
        _marker: PhantomData, 
    };
    #[rustfmt::skip]
    const R2: MpcBigInteger<F, S, T> = MpcBigInteger::<F, S, T>{
        val: <<F as PrimeField>::Parameters as FieldParameters>::R2,
        _marker: PhantomData, 
    };
    #[rustfmt::skip]
    const REPR_SHAVE_BITS: u32 = 3;
    // T and T_MINUS_ONE_DIV_TWO, where r - 1 = 2^s * t

    /// t = (r - 1) / 2^s =
    /// 60001509534603559531609739528203892656505753216962260608619555
    #[rustfmt::skip]
    const T: MpcBigInteger<F, S, T> = MpcBigInteger::<F, S, T>{
        val: <<F as PrimeField>::Parameters as FieldParameters>::T,
        _marker: PhantomData, 
    };
    /// (t - 1) / 2 =
    /// 30000754767301779765804869764101946328252876608481130304309777
    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: MpcBigInteger<F, S, T> = MpcBigInteger::<F, S, T>{
        val: <<F as PrimeField>::Parameters as FieldParameters>::T_MINUS_ONE_DIV_TWO,
        _marker: PhantomData, 
    };
}

// Copy of bls12_377::FrParameters
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: _BigInteger> PoseidonDefaultParameters for MpcFrParameters<F, S, T> {
    const PARAMS_OPT_FOR_CONSTRAINTS: [PoseidonDefaultParametersEntry; 7] = [
        PoseidonDefaultParametersEntry::new(2, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(3, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(4, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(5, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(6, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(7, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(8, 17, 8, 31, 0),
    ];
}

impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: _BigInteger> Hash for MpcFrParameters<F, S, T> {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        unimplemented!("MpcFrParameters::hash");
    }
}

impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: _BigInteger> Default for MpcFrParameters<F, S, T> {
    #[inline]
    fn default() -> Self {
        unimplemented!("MpcFrParameters::default");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_curves::bls12_377::Fr; // TODO: try all fields
    // use snarkvm_curves::bls12_377::FqParameters;
    // mpc_algebra::share::spdz::SpdzPairingShare<E>::FqShare : FieldShare<Fq>
    // type MpcFrParametersInst = MpcFrParameters<Fq, FieldShare<Fq>, _BigInteger>;
    use snarkvm_fields::{FftField, Field, PrimeField};

    #[test]
    fn test_powers_of_root_of_unity() {
        let two = Fr::from(2u8); // TODO: should we be supporting Fq?

        // Compute the expected powers of root of unity.
        let root_of_unity = Fr::two_adic_root_of_unity();
        // TODO: does the choice of *FieldShare matter? Should we try all of them?
        let powers = (0..MpcFrParameters::<Fr, crate::SpdzFieldShare<Fr>, _>::TWO_ADICITY - 1)
            .map(|i| root_of_unity.pow(two.pow(Fr::from(i as u64).to_bigint()).to_bigint()))
            .collect::<Vec<_>>();
        assert_eq!(powers[0], Fr::two_adic_root_of_unity());

        // Ensure the correct number of powers of root of unity are present.
        assert_eq!(MpcFrParameters::<Fr, crate::SpdzFieldShare<Fr>, _>::POWERS_OF_ROOTS_OF_UNITY().len() as u64, (MpcFrParameters::<Fr, crate::SpdzFieldShare<Fr>, _>::TWO_ADICITY - 1) as u64);
        assert_eq!(MpcFrParameters::<Fr, crate::SpdzFieldShare<Fr>, _>::POWERS_OF_ROOTS_OF_UNITY().len(), powers.len());

        // Ensure the expected and candidate powers match.
        for (expected, candidate) in powers.iter().zip(MpcFrParameters::<Fr, crate::SpdzFieldShare<Fr>, _>::POWERS_OF_ROOTS_OF_UNITY()) {
            // println!("BigInteger({:?}),", expected.0.0);
            println!("{:?} =?= {:?}", expected.0, candidate);
            assert_eq!(expected.0, candidate.val);
        }
    }

    #[test]
    fn test_two_adic_root_of_unity() {
        // TODO: is this the right BigInteger type?
        let expected = Fr::multiplicative_generator().pow::<snarkvm_utilities::BigInteger256>(MpcFrParameters::<Fr, crate::SpdzFieldShare<Fr>, _>::T.val);
        assert_eq!(expected, Fr::two_adic_root_of_unity());
    }
}
