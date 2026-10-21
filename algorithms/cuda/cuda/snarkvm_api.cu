// Copyright (c) 2019-2026 Provable Inc.
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

#include <cuda.h>

#include "snarkvm.cu"

#ifndef __CUDA_ARCH__

// Lazy instantiation of snarkvm_t
class snarkvm_singleton_t {
    std::once_flag once;
    snarkvm_t *snarkvm = nullptr;

    // Never throws: `std::call_once` does not mark a call that throws as
    // done, so the next call would build the pool again.
    void init() noexcept {
        try {
            // With no usable GPU, `snarkvm_t` builds an empty slot pool, and
            // the first call waits forever for a slot.
            if (ngpus() == 0) {
                return;
            }
            // SNP TODO: max domain size?
            snarkvm = new snarkvm_t(17);
        } catch (...) {
            snarkvm = nullptr;
        }
    }

public:
    snarkvm_singleton_t() {}
    ~snarkvm_singleton_t() {
        delete snarkvm;
        snarkvm = nullptr;
    }
    // Builds the pool once, however many threads make the first call.
    bool ok() {
        std::call_once(once, [this] { init(); });
        return snarkvm != nullptr;
    }
    snarkvm_t* operator->() {
        assert (ok());
        return snarkvm;
    }
};
snarkvm_singleton_t snarkvm_g;

// blst's portable routines choose ADX from `__blst_platform_cap`, which a
// constructor in blst's `server.c` sets from CPUID. Nothing else here calls
// into `server.c`, so without this reference the linker drops it, the flag
// stays 0, and ADX is never used.
extern "C" size_t blst_p1_sizeof(void);
__attribute__((used)) static size_t (*const keep_blst_cpuid)(void) = blst_p1_sizeof;
extern "C" int __blst_platform_cap;

// sppark reports device failures by throwing, and an exception that crosses
// `extern "C"` into Rust is undefined behaviour.
template<class F> static RustError catch_all(F f) noexcept
{
    try {
        return f();
    } catch (const cuda_error& e) {
        return RustError{e.code(), e.what()};
    } catch (...) {
        return RustError{cudaErrorUnknown};
    }
}

#ifndef __CUDA_ARCH__

extern "C" {
    int snarkvm_blst_platform_cap()
    {
        return __blst_platform_cap;
    }

    RustError snarkvm_ntt(fr_t* inout, uint32_t lg_domain_size,
                          NTT::InputOutputOrder ntt_order, NTT::Direction ntt_direction,
                          NTT::Type ntt_type)
    {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return RustError{cudaErrorMemoryAllocation};
            }
            return snarkvm_g->NTT(inout, inout, lg_domain_size, ntt_order,
                                  ntt_direction, ntt_type);
        });
    }

    RustError snarkvm_polymul(fr_t* out,
                              size_t pcount, fr_t** polynomials, size_t* plens,
                              size_t ecount, fr_t** evaluations, size_t* elens,
                              uint32_t lg_domain_size) {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return RustError{cudaErrorMemoryAllocation};
            }
            return snarkvm_g->PolyMul(out,
                                      pcount, polynomials, plens,
                                      ecount, evaluations, elens,
                                      lg_domain_size);
        });
    }

    RustError snarkvm_msm(point_t* out, const affine_t points[], size_t npoints,
                          const scalar_t scalars[], size_t ffi_affine_size) {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return RustError{cudaErrorMemoryAllocation};
            }
            return snarkvm_g->MSM(out, points, npoints, scalars, ffi_affine_size);
        });
    }
}
#endif // __CUDA_ARCH__

#endif
