// Copyright 2024 Aleo Network Foundation
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::ops::{Add, AddAssign, MulAssign};

use crate::{
    templates::short_weierstrass_jacobian::{Affine as SWAffine, Projective as SWProjective},
    traits::ShortWeierstrassParameters, Group,
};

impl<M: ShortWeierstrassParameters> Group for SWAffine<M>
{
    type ScalarField = M::ScalarField;

    #[inline]
    fn double(&self) -> Self {
        *self + *self
    }

    #[inline]
    fn double_in_place(&mut self) -> &mut Self {
        *self += self.clone();
        self
    }

    #[inline]
    fn mul<'a>(&self, other: &'a Self::ScalarField) -> Self {
        let mut copy = *self;
        copy *= *other;
        copy
    }
}

impl<M: ShortWeierstrassParameters> Add<SWAffine<M>> for SWAffine<M>
{
    type Output = SWAffine<M>;

    fn add(self, other: SWAffine<M>) -> SWAffine<M> {
        let mut result = self;
        result += other;
        result
    }
}

impl<M: ShortWeierstrassParameters> AddAssign<SWAffine<M>> for SWAffine<M>
{
    fn add_assign(&mut self, other: SWAffine<M>) {
        *self = (SWProjective::from(*self) + SWProjective::from(other)).into();
    }
}

impl<M: ShortWeierstrassParameters> MulAssign<M::ScalarField> for SWAffine<M>
{
    fn mul_assign(&mut self, other: M::ScalarField) {
        *self = (SWProjective::from(*self) * other).into();
    }
}



impl<M: ShortWeierstrassParameters> Group for SWProjective<M>
{
    type ScalarField = M::ScalarField;

    #[inline]
    fn double(&self) -> Self {
        *self + *self
    }

    #[inline]
    fn double_in_place(&mut self) -> &mut Self {
        *self += self.clone();
        self
    }

    #[inline]
    fn mul<'a>(&self, other: &'a Self::ScalarField) -> Self {
        let mut copy = *self;
        copy *= *other;
        copy
    }
}