#![allow(unused)]
use crate::{
    codec::Codec,
    context::{Context, FftBuffer},

    // NOTE(abheet): these two commented out functions were not being used
    // anywhere.
    // lwe::{conv_lwe_to_rlwe, LWECiphertext, LWEtoRLWEKeyswitchKey},
    lwe::{/* conv_lwe_to_rlwe, */ LWECiphertext, /* LWEtoRLWEKeyswitchKey */},

    num_types::{Complex, ComplexContaier, One, Scalar, ScalarContainer, SignedScalar, Zero},
    rgsw::RGSWCiphertext,
    utils::{eval_x_k, log2, mul_const},
};

// NOTE(abheet): old concrete_core things, replaced with tfhe-rs things.
/*
use concrete_core::{
    backends::fft::private::math::{fft::Fft, polynomial::FourierPolynomial},
    commons::{
        crypto::{
            encoding::{Plaintext, PlaintextList},
            glwe::{GlweBody, GlweCiphertext, GlweMask},
            secret::{
                generators::{EncryptionRandomGenerator, SecretRandomGenerator},
                GlweSecretKey,
            },
        },
        math::{
            decomposition::SignedDecomposer,
            polynomial::{MonomialDegree, Polynomial},
            tensor::{AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, Tensor},
        },
    },
    prelude::{
        BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, DispersionParameter,
        GlweDimension, PlaintextCount, PolynomialSize,
    },
};

use concrete_csprng::generators::SoftwareRandomGenerator;
use dyn_stack::{DynStack, GlobalMemBuffer, ReborrowMut};
*/

use tfhe::{
    core_crypto::prelude::{Fft, FourierPolynomial},

    core_crypto::entities::plaintext::Plaintext,
    core_crypto::entities::plaintext_list::PlaintextList,
    core_crypto::entities::glwe_ciphertext::{GlweBody, GlweCiphertext, GlweMask},

    core_crypto::commons::generators::{
        EncryptionRandomGenerator,
        SecretRandomGenerator,
    },

    core_crypto::entities::glwe_secret_key::GlweSecretKey,

    core_crypto::commons::math::decomposition::SignedDecomposer,
    core_crypto::commons::parameters::MonomialDegree,
    core_crypto::entities::polynomial::Polynomial,

    core_crypto::commons::parameters::DecompositionBaseLog,
    core_crypto::commons::parameters::DecompositionLevelCount,
    core_crypto::commons::dispersion::DispersionParameter,

    core_crypto::commons::parameters::{GlweDimension, PlaintextCount, PolynomialSize},

    // Newly added.
    core_crypto::commons::ciphertext_modulus::CiphertextModulus,
    core_crypto::algorithms::polynomial_algorithms::{
        // TODO(abheet): they should be replaced with `_custom_modulus`
        // versions.
        polynomial_wrapping_mul,
        polynomial_wrapping_add_mul_assign,
        polynomial_wrapping_add_assign,
        polynomial_wrapping_sub_assign,
    },
    core_crypto::algorithms::slice_algorithms::{
        // TODO(abheet): they should be replaced with `_custom_modulus`
        // versions.
        slice_wrapping_add_assign, 
        slice_wrapping_sub_assign,
        slice_wrapping_sub_assign_custom_mod,
    },
    core_crypto::prelude::{Container, ContainerMut},
    core_crypto::fft_impl::fft128::math::fft::Fft128,

    core_crypto::algorithms::glwe_encryption::encrypt_glwe_ciphertext,
    core_crypto::algorithms::glwe_encryption::decrypt_glwe_ciphertext,

    core_crypto::commons::math::random::{UniformBinary, UniformTernary},
    core_crypto::commons::math::random::Distribution,

    core_crypto::prelude::{ContiguousEntityContainer, ContiguousEntityContainerMut},

    core_crypto::algorithms::ggsw_encryption::encrypt_constant_ggsw_ciphertext,
    core_crypto::prelude::Cleartext,

    core_crypto::fft_impl::fft128::math::polynomial::Fourier128Polynomial,
};

use tfhe_csprng::generators::SoftwareRandomGenerator;
use dyn_stack::{DynStack, MemBuffer, PodBuffer, PodStack};

use std::collections::HashMap;

#[derive(Debug, Clone)]
/// An RLWE ciphertext.
/// It is a wrapper around `GlweCiphertext` from concrete.
pub struct RLWECiphertext(pub(crate) GlweCiphertext<ScalarContainer>);

impl RLWECiphertext {
    // NOTE(abheet): now it takes an extra argument `modulus`.
    pub fn allocate(
        poly_size: PolynomialSize,
        modulus: CiphertextModulus<Scalar>
    ) -> Self {
        Self(GlweCiphertext::from_container(
            vec![Scalar::zero(); poly_size.0 * 2],
            poly_size,
            modulus,
        ))
    }

    // NOTE(abheet): new function added!
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.0.ciphertext_modulus()
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    pub fn get_body(&self) -> GlweBody<&[Scalar]> {
        self.0.get_body()
    }

    pub fn get_mask(&self) -> GlweMask<&[Scalar]> {
        self.0.get_mask()
    }

    pub fn get_mut_mask(&mut self) -> GlweMask<&mut [Scalar]> {
        self.0.get_mut_mask()
    }

    pub fn get_mut_body(&mut self) -> GlweBody<&mut [Scalar]> {
        self.0.get_mut_body()
    }

    pub fn clear(&mut self) {
        // NOTE(abheet): no tensor in tfhe
        // self.0.as_mut_tensor().fill_with(Scalar::zero);

        self.0.as_mut().fill_with(Scalar::zero);
    }

    pub fn fill_with_copy(&mut self, other: &RLWECiphertext) {
        // NOTE(abheet): no tensor in tfhe
        // self.0.as_mut_tensor().fill_with_copy(other.0.as_tensor());

        self.0.as_mut().copy_from_slice(other.0.as_ref());
    }

    // NOTE(abheet): modified! and replaced with `fill_with_slice`
    // Does not uses tensor api in the modified version.
    /*
    pub fn fill_with_tensor<C>(&mut self, t: &Tensor<C>)
    where
        Tensor<C>: AsRefSlice<Element = Scalar>,
    {
        self.0.as_mut_tensor().fill_with_copy(t);
    }
    */

    pub fn fill_with_slice<C>(&mut self, s: C)
    where
        C: Container<Element = Scalar>,
    {
        self.0.as_mut().copy_from_slice(s.as_ref());
    }

    // NOTE(abheet): modified!
    //
    // pub fn update_mask_with_add<C>(&mut self, other: &Polynomial<C>)
    // where
    //     C: AsRefSlice<Element = Scalar>,
    // {
    //     self.get_mut_mask()
    //         .as_mut_polynomial_list()
    //         .get_mut_polynomial(0)
    //         .update_with_wrapping_add(other);
    // }

    pub fn update_mask_with_add<C>(&mut self, other: &Polynomial<C>)
    where
        C: Container<Element = Scalar>,
    {
        // TODO(abheet): is this correct?
        slice_wrapping_add_assign(
            self.get_mut_mask()
                .as_mut_polynomial_list()
                .iter_mut()
                .next()
                .unwrap()
                .as_mut(),
            &other.as_ref()[..]
        );
    }

    // NOTE(abheet): modified!
    //
    // pub fn update_mask_with_sub(&mut self, other: &Polynomial<&[Scalar]>) {
    //     self.get_mut_mask()
    //         .as_mut_polynomial_list()
    //         .get_mut_polynomial(0)
    //         .update_with_wrapping_sub(other);
    // }

    pub fn update_mask_with_sub(&mut self, other: &Polynomial<&[Scalar]>) {
        // TODO(abheet): is this correct?
        slice_wrapping_sub_assign(
            self.get_mut_mask()
                .as_mut_polynomial_list()
                .iter_mut()
                .next()
                .unwrap()
                .as_mut(),
            &other.as_ref()[..]
        );
    }

    // NOTE(abheet): modified!
    //
    // pub fn update_mask_with_mul(&mut self, other: &Polynomial<&mut [Scalar]>) {
    //     let mut poly_buffer = Polynomial::allocate(Scalar::zero(), self.polynomial_size());
    //     poly_buffer
    //         .as_mut_tensor()
    //         .fill_with_copy(self.get_mask().as_tensor());
    //     self.get_mut_mask().as_mut_tensor().fill_with(Scalar::zero);

    //     naive_update_with_mul_acc(
    //         &mut self
    //             .get_mut_mask()
    //             .as_mut_polynomial_list()
    //             .get_mut_polynomial(0),
    //         &poly_buffer.as_mut_view(),
    //         other,
    //     );
    // }

    pub fn update_mask_with_mul(&mut self, other: &Polynomial<&mut [Scalar]>) {
        let mut poly_buffer = Polynomial::new(Scalar::zero(), self.polynomial_size());

        poly_buffer
            .as_mut()
            .copy_from_slice(self.get_mask().as_ref());
        self.get_mut_mask().as_mut().fill_with(Scalar::zero);

        // TODO(abheet): is this correct? - apurba: yes this is working 
        naive_update_with_mul_acc(
            &mut self.get_mut_mask()
                .as_mut_polynomial_list()
                .iter_mut()
                .next()
                .unwrap(),
            &poly_buffer.as_mut_view(),
            other,
        );
    }

    // NOTE(abheet): modified!
    //
    // pub fn update_mask_with_mul_with_buf(&mut self, other: &Polynomial<&[Scalar]>) {
    //     fourier_update_with_mul(
    //         &mut self
    //             .get_mut_mask()
    //             .as_mut_polynomial_list()
    //             .get_mut_polynomial(0),
    //         other,
    //     );
    // }

    pub fn update_mask_with_mul_with_buf(&mut self, other: &Polynomial<&[Scalar]>) {
        let poly_size = self.0.polynomial_size().0;
        let mut foo = self.get_mut_mask();
        let mut bar = foo.as_mut_polynomial_list();
        let mut fizz = &mut bar.as_mut()[(0 * poly_size)..(1 * poly_size)];
        let mut buzz = Polynomial::from_container(fizz);

        fourier_update_with_mul(
            &mut self.get_mut_mask()
                .as_mut_polynomial_list()
                .iter_mut()
                .next()
                .unwrap(),
            other
        );
    }

    // NOTE(abheet): modified!
    //
    // pub fn update_body_with_add<C>(&mut self, other: &Polynomial<C>)
    // where
    //     C: AsRefSlice<Element = Scalar>,
    // {
    //     self.get_mut_body()
    //         .as_mut_polynomial()
    //         .update_with_wrapping_add(other);
    // }

    pub fn update_body_with_add<C>(&mut self, other: &Polynomial<C>)
    where
        C: Container<Element = Scalar>,
    {
        polynomial_wrapping_add_assign(
            &mut self.get_mut_body().as_mut_polynomial(),
            other
        );
    }

    // NOTE(abheet): modified!
    //
    // pub fn update_body_with_sub(&mut self, other: &Polynomial<&[Scalar]>) {
    //     self.get_mut_body()
    //         .as_mut_polynomial()
    //         .update_with_wrapping_sub(other);
    // }

    pub fn update_body_with_sub(&mut self, other: &Polynomial<&[Scalar]>) {
        polynomial_wrapping_sub_assign(
            &mut self.get_mut_body().as_mut_polynomial(),
            other
        )
    }

    pub fn update_body_with_mul(&mut self, other: &Polynomial<&mut [Scalar]>) {
        // NOTE(abheet): no tensor in tfhe.
        // BTW...isn't this multiplication wrong? - apurba: yes it is wrong
        //
        /*
        let mut poly_buffer = Polynomial::allocate(
            Scalar::zero(), self.polynomial_size());

        poly_buffer
            .as_mut_tensor()
            .fill_with_copy(self.get_body().as_tensor());
        self.get_mut_body().as_mut_tensor().fill_with(Scalar::zero);
        naive_update_with_mul(&mut self.get_mut_body().as_mut_polynomial(), other);
        */

        let mut poly_buffer = Polynomial::new(Scalar::zero(), self.polynomial_size());

        poly_buffer
            .as_mut()
            .copy_from_slice(self.get_body().as_ref());

        // naive_update_with_mul(&mut poly_buffer, other);
        // self.get_mut_body().as_mut().copy_from_slice(poly_buffer.as_ref());
        
        // apurba - fixed
        self.get_mut_body().as_mut().fill_with(Scalar::zero);
        naive_update_with_mul_acc(
            &mut self.get_mut_body().as_mut_polynomial(),
            &poly_buffer.as_mut_view(),
            other,
        );
    }

    pub fn update_body_with_mul_with_buf(&mut self, other: &Polynomial<&[Scalar]>) {
        fourier_update_with_mul(&mut self.get_mut_body().as_mut_polynomial(), other);
    }

    pub fn update_with_add(&mut self, other: &RLWECiphertext) {

        // NOTE(abheet): modified iteration method.
        //
        // self.update_mask_with_add(&other.get_mask().as_polynomial_list().get_polynomial(0));
        // self.update_body_with_add(&other.get_body().as_polynomial());

        self.update_mask_with_add(
            &other.get_mask().as_polynomial_list().iter().next().unwrap()
        );
        self.update_body_with_add(&other.get_body().as_polynomial());
    }

    pub fn update_with_sub(&mut self, other: &RLWECiphertext) {
        // NOTE(abheet): modified iteration method.
        //
        // self.update_mask_with_sub(&other.get_mask().as_polynomial_list().get_polynomial(0));
        // self.update_body_with_sub(&other.get_body().as_polynomial());

        self.update_mask_with_sub(
            &other.get_mask().as_polynomial_list().iter().next().unwrap()
        );
        self.update_body_with_sub(&other.get_body().as_polynomial());
    }

    // NOTE(abheet): not needed right now.
    //
    // pub fn update_with_monomial_div(&mut self, m: MonomialDegree) {
    //     self.get_mut_body()
    //         .as_mut_polynomial()
    //         .update_with_wrapping_unit_monomial_div(m);
    //     self.get_mut_mask()
    //         .as_mut_polynomial_list()
    //         .get_mut_polynomial(0)
    //         .update_with_wrapping_unit_monomial_div(m);
    // }

    /// Run the `trace1(RLWE(\sum_i` `a_i` X^i)) = `RLWE((1/N)*a_0`) operation on this ciphertext.
    pub fn trace1(&self, ksk_map: &HashMap<usize, RLWEKeyswitchKey>) -> Self {
        let n = self.0.polynomial_size().0;

        // NOTE(abheet): takes extra argument, the ciphertext modulus.
        let mut buf = Self::allocate(PolynomialSize(n), self.ciphertext_modulus());
        let mut out = Self(self.0.clone());
        for i in 1..=log2(n) {
            let k = n / (1 << (i - 1)) + 1;
            let ksk = ksk_map.get(&k).unwrap();
            assert_eq!(ksk.get_subs_k(), k);
            ksk.subs(&mut buf, &out);
            out.update_with_add(&buf);
        }
        out
    }

    // NOTE(abheet): modified!
    //
    // pub fn trace1_fourier(
    //     &self,
    //     out: &mut RLWECiphertext,
    //     ksk_map: &HashMap<usize, FourierRLWEKeyswitchKey>,
    // ) {
    //     let n = self.0.polynomial_size().0;

    //     let fft = Fft::new(PolynomialSize(n));
    //     let fft = fft.as_view();

    //     let mut mem = GlobalMemBuffer::new(
    //         fft.forward_scratch()
    //             .unwrap()
    //             .and(fft.backward_scratch().unwrap()),
    //     );
    //     let mut stack = DynStack::new(&mut mem);

    //     out.0.as_mut_tensor().fill_with_copy(self.0.as_tensor());

    //     // TODO remove allocation
    //     let mut buf_fourier = FourierRLWECiphertext::new(n);

    //     for i in 1..=log2(n) {
    //         let k = n / (1 << (i - 1)) + 1;
    //         let ksk = ksk_map.get(&k).unwrap();

    //         assert_eq!(ksk.get_subs_k(), k);
    //         ksk.subs(&mut buf_fourier, out);

    //         fft.add_backward_as_torus(
    //             out.get_mut_mask()
    //                 .as_mut_polynomial_list()
    //                 .get_mut_polynomial(0),
    //             buf_fourier.mask.as_view(),
    //             stack.rb_mut(),
    //         );

    //         fft.add_backward_as_torus(
    //             out.get_mut_body().as_mut_polynomial(),
    //             buf_fourier.body.as_view(),
    //             stack.rb_mut(),
    //         );
    //     }
    // }

    /// Run the `trace1(RLWE(\sum_i` `a_i` X^i)) = `RLWE((1/N)*a_0`) operation on this ciphertext
    /// using key switching keys in the fourier domain.
    pub fn trace1_fourier(
        &self,
        out: &mut RLWECiphertext,
        ksk_map: &HashMap<usize, FourierRLWEKeyswitchKey>,
    ) {
        let n = self.0.polynomial_size().0;

        let fft = Fft128::new(PolynomialSize(n));
        let fft = fft.as_view();

        let mut buffer = PodBuffer::new(fft.backward_scratch());
        let mut stack = PodStack::new(&mut buffer);

        out.0.as_mut().copy_from_slice(self.0.as_ref());

        // TODO remove allocation
        let mut buf_fourier = Fourier128RLWECiphertext::new(n, self.ciphertext_modulus());

        for i in 1..=log2(n) {
            let k = n / (1 << (i - 1)) + 1;
            let ksk = ksk_map.get(&k).unwrap();

            assert_eq!(ksk.get_subs_k(), k);
            ksk.subs(&mut buf_fourier, out);

            /*
            fft.add_backward_as_torus(
                out.get_mut_mask()
                    .as_mut_polynomial_list()
                    .get_mut_polynomial(0),
                buf_fourier.mask.as_view(),
                stack.rb_mut(),
            );
            */

            fft.add_backward_as_torus(
                out.get_mut_mask().as_mut_polynomial_list().iter_mut().next()
                    .unwrap().as_mut(),
                &buf_fourier.mask.data_re0,
                &buf_fourier.mask.data_re1,
                &buf_fourier.mask.data_im0,
                &buf_fourier.mask.data_im0,
                &mut stack,
            );

            /*
            fft.add_backward_as_torus(
                out.get_mut_body().as_mut_polynomial(),
                buf_fourier.body.as_view(),
                stack.rb_mut(),
            );
            */

            fft.add_backward_as_torus(
                out.get_mut_body().as_mut_polynomial().as_mut(),
                &buf_fourier.body.data_re0,
                &buf_fourier.body.data_re1,
                &buf_fourier.body.data_im0,
                &buf_fourier.body.data_im0,
                &mut stack,
            );
        }
    }

    /// Compare this ciphertext c, which encrypts m on the exponent against a value d
    /// the resulting ciphertext encrypts a polynomial m(X) such that
    /// m0 = 1 if m <= d, otherwise m0 = 0, where m0 is the constant term of m(X).
    /// Note that encrypting on the exponent means m -> X^m.
    pub fn less_eq_than(&mut self, d: usize) {
        let n = self.polynomial_size().0;
        assert!(d < n);
        let t_poly = {
            let mut t = vec![Scalar::zero(); n];
            t[0] = Scalar::one();
            for x in t.iter_mut().take(n).skip(n - d) {
                *x = Scalar::MAX; // -1
            }
            Polynomial::from_container(t)
        };

        self.update_body_with_mul_with_buf(&t_poly.as_view());
        self.update_mask_with_mul_with_buf(&t_poly.as_view());
    }

    /// Checks whether this ciphertext c, which encrypts a value m on the exponent
    /// equals to d.
    pub fn eq_to(&mut self, d: usize) {
        let n = self.polynomial_size().0;
        assert!(d < n);
        let t_poly = {
            let mut t = vec![Scalar::zero(); n];
            if d == 0 {
                t[0] = Scalar::one();
            } else {
                t[n - d] = Scalar::MAX;
            }
            Polynomial::from_container(t)
        };

        self.update_body_with_mul_with_buf(&t_poly.as_view());
        self.update_mask_with_mul_with_buf(&t_poly.as_view());
    }

    // NOTE(abheet): no tensor in tfhe!
    /// Run the not gate on this ciphertext, the ciphertext must encrypt a binary scalar.
    /// If c = (a, b = a s + e + q/2 b), then negating it becomes
    /// (-a, q/2 - b) = (-a, -a s - e + q/2 NOT(b))
    pub fn not_in_place(&mut self) {
        let delta = Scalar::one() << (Scalar::BITS - 1);
        for x in self.0.as_mut().iter_mut() {
            *x = Scalar::zero().wrapping_sub(*x);
        }
        *self.get_mut_body().as_mut().first_mut().unwrap() =
            (*self.get_body().as_ref().first().unwrap()).wrapping_add(delta);
    }

    // NOTE(abheet): no tensor in tfhe!
    /// Return NOT(self) where self must encrypt a binary scalar.
    pub fn not(&self) -> Self {
        let delta = Scalar::one() << (Scalar::BITS - 1);
        let mut out = Self::allocate(self.polynomial_size(), self.0.ciphertext_modulus());
        slice_wrapping_sub_assign_custom_mod(
            out.0.as_mut(),
            self.0.as_ref(),
            self.0.ciphertext_modulus().get_custom_modulus_as_optional_scalar().unwrap(),
        );
        *out.get_mut_body().as_mut().first_mut().unwrap() =
            (*out.get_body().as_ref().first().unwrap()).wrapping_add(delta);
        out
    }
}

#[derive(Debug, Clone)]
/// An RLWE secret key.
pub struct RLWESecretKey(pub(crate) GlweSecretKey<Vec<Scalar>>);

impl RLWESecretKey {
    /// Generate a secret key where the coefficients are binary.
    pub fn generate_binary(
        poly_size: PolynomialSize,
        generator: &mut SecretRandomGenerator<SoftwareRandomGenerator>,
    ) -> Self {
        Self(GlweSecretKey::generate_new_binary(
            GlweDimension(1),
            poly_size,
            generator,
        ))
    }

    /// Generate a trivial secret key where the coefficients are all zero.
    pub fn zero(poly_size: PolynomialSize) -> Self {
        Self(GlweSecretKey::from_container(
            vec![Scalar::zero(); poly_size.0],
            poly_size,
        ))
    }

    // NOTE(abheet): renamed to `fill_with_slice`
    //
    // pub fn fill_with_tensor<C>(&mut self, t: &Tensor<C>)
    // where
    //     Tensor<C>: AsRefSlice<Element = Scalar>,
    // {
    //     self.0.as_mut_tensor().fill_with_copy(t);
    // }

    pub fn fill_with_slice<C>(&mut self, s: C)
    where
        C: Container<Element = Scalar>,
    {
        self.0.as_mut().copy_from_slice(s.as_ref());
    }

    // NOTE(abheet): this have been split into _binary and _ternary versions
    // that take UniformBinary and UniformTernary distribution as arguments to
    // `poly_encode` internally.
    //
    // TODO(abheet): is this the right thing to do?...probably not!
    //
    // /// Encode and then encrypt the plaintext pt.
    // pub fn encode_encrypt_rlwe(
    //     &self,
    //     encrypted: &mut RLWECiphertext,
    //     pt: &PlaintextList<Vec<Scalar>>,
    //     ctx: &mut Context,
    // ) {
    //     let mut binary_encoded = pt.clone();
    //     ctx.codec
    //         .poly_encode(&mut binary_encoded.as_mut_polynomial());
    //     self.encrypt_rlwe(
    //         encrypted,
    //         &binary_encoded,
    //         ctx.std,
    //         &mut ctx.encryption_generator,
    //     );
    // }

    // NOTE(abheet): renamed from `encode_encrypt_rlwe`
    /// Encode and then encrypt the plaintext pt.
    pub fn encode_encrypt_rlwe_binary( /* encode_encrypt_rlwe */
        &self,
        encrypted: &mut RLWECiphertext,
        pt: &PlaintextList<Vec<Scalar>>,
        ctx: &mut Context,
    ) {
        let mut binary_encoded = pt.clone();
        ctx.codec
            .poly_encode(&mut binary_encoded.as_mut_polynomial());
        self.encrypt_rlwe_binary(
            encrypted,
            &binary_encoded,
            // TODO(abheet): is this correct? - apurba: yes encode_encrypt_rlwe_binary seems to work
            // ctx.std,
            UniformBinary,
            &mut ctx.encryption_generator,
        );
    }

    // NOTE(abheet): renamed from `ternary_encrypt_rlwe`
    /// Encode and then encrypt the plaintext pt.
    pub fn encode_encrypt_rlwe_ternary( /* ternary_encrypt_rlwe */
        &self,
        encrypted: &mut RLWECiphertext,
        pt: &PlaintextList<Vec<Scalar>>,
        ctx: &mut Context,
    ) {
        let mut ternary_encoded = pt.clone();
        Codec::poly_ternary_encode(&mut ternary_encoded.as_mut_polynomial());
        self.encrypt_rlwe_ternary(
            encrypted,
            &ternary_encoded,
            // TODO(abheet): is this correct?
            // ctx.std,
            UniformTernary,
            &mut ctx.encryption_generator,
        );
    }

    // NOTE(abheet): modified!, split into binary and ternary versions and use
    // newer tfhe-rs APIs
    //
    // /// Encrypt a plaintext pt.
    // // TODO change API to use Context
    // pub fn encrypt_rlwe(
    //     &self,
    //     encrypted: &mut RLWECiphertext,
    //     pt: &PlaintextList<Vec<Scalar>>,
    //     noise_parameter: impl DispersionParameter,
    //     generator: &mut EncryptionRandomGenerator<SoftwareRandomGenerator>,
    // ) {
    //     self.0
    //         .encrypt_glwe(&mut encrypted.0, pt, noise_parameter, generator);
    // }

    /// Encrypt a plaintext pt.
    // TODO: change API to use Context
    // NOTE(abheet): this is the binary version, ternary version also exists.
    pub fn encrypt_rlwe_binary(
        &self,
        encrypted: &mut RLWECiphertext,
        pt: &PlaintextList<Vec<Scalar>>,
        // noise_parameter: impl DispersionParameter,
        noise_parameter: UniformBinary, // NOTE(abheet): is it sound?
        generator: &mut EncryptionRandomGenerator<SoftwareRandomGenerator>,
    ) {
        // abheet: use the newer `encrypt_glwe_ciphertext` function from tfhe-rs.
        encrypt_glwe_ciphertext(
            &self.0,
            &mut encrypted.0,
            pt,
            noise_parameter,
            generator,
        );
    }

    // NOTE(abheet): the ternary version.
    pub fn encrypt_rlwe_ternary(
        &self,
        encrypted: &mut RLWECiphertext,
        pt: &PlaintextList<Vec<Scalar>>,
        noise_parameter: UniformTernary, // NOTE(abheet): is it sound?
        generator: &mut EncryptionRandomGenerator<SoftwareRandomGenerator>,
    ) {
        encrypt_glwe_ciphertext(
            &self.0,
            &mut encrypted.0,
            pt,
            noise_parameter,
            generator,
        );
    }

    // NOTE(abheet): modified!
    /// Encrypt a scalar.
    pub fn encrypt_constant_rlwe(
        &self,
        encrypted: &mut RLWECiphertext,
        pt: &Plaintext<Scalar>,
        ctx: &mut Context,
    ) {
        let mut encoded = PlaintextList::new(Scalar::zero(), ctx.plaintext_count());
        /*
        *encoded
            .as_mut_polynomial()
            .get_mut_monomial(MonomialDegree(0))
            .get_mut_coefficient() = pt.0;
        */

        // TODO(abheet): its a hack but is it correct?
        // Setting the first value in the array to be pt.0
        encoded.as_mut_polynomial().as_mut()[0] = pt.0;

        // abheet: use the newer `encrypt_glwe_ciphertext` function from tfhe-rs.
        encrypt_glwe_ciphertext(
            &self.0,
            &mut encrypted.0,
            &encoded,
            // ctx.std,
            UniformBinary, // TODO(abheet): is it correct?
            &mut ctx.encryption_generator,
        );
    }

    // NOTE(abheet): modified!
    /// Decrypt a RLWE ciphertext.
    pub fn decrypt_rlwe(&self, pt: &mut PlaintextList<Vec<Scalar>>, encrypted: &RLWECiphertext) {
        // abheet: use the newer `decrypt_glwe_ciphertext` function from tfhe-rs.
        decrypt_glwe_ciphertext(
            &self.0,
            &encrypted.0,
            pt,
        );
    }

    /// Decrypt a RLWE ciphertext and then decode.
    pub fn decrypt_decode_rlwe(
        &self,
        pt: &mut PlaintextList<Vec<Scalar>>,
        encrypted: &RLWECiphertext,
        ctx: &Context,
    ) {
        self.decrypt_rlwe(pt, encrypted);
        ctx.codec.poly_decode(&mut pt.as_mut_polynomial());
    }

    /// Decrypt a RLWE ciphertext and then decode.
    pub fn ternary_decrypt_rlwe(
        &self,
        pt: &mut PlaintextList<Vec<Scalar>>,
        encrypted: &RLWECiphertext,
    ) {
        self.decrypt_rlwe(pt, encrypted);
        Codec::poly_ternary_decode(&mut pt.as_mut_polynomial());
    }

    // NOTE(abheet): modified!
    /// Create an RGSW ciphertext of a constant.
    pub fn encrypt_constant_rgsw(
        &self,
        out: &mut RGSWCiphertext,
        pt: &Plaintext<Scalar>,
        ctx: &mut Context,
    ) {
        // self.0.encrypt_constant_ggsw(
        //     &mut out.0,
        //     pt,
        //     ctx.std,
        //     &mut ctx.encryption_generator
        // );

        // abheet: use this newer function.
        encrypt_constant_ggsw_ciphertext(
            &self.0,
            &mut out.0,
            Cleartext(pt.0),
            UniformBinary, // TODO(abheet): is this correct?
            &mut ctx.encryption_generator,
        );

        // NOTE:for debugging we can use
        // self.0.trivial_encrypt_constant_ggsw(&mut out.0, encoded, ctx.std, &mut ctx.encryption_generator)
    }

    /// Create an RGSW ciphertext of a polynomial.
    pub fn encrypt_rgsw(
        &self,
        out: &mut RGSWCiphertext,
        encoded: &PlaintextList<Vec<Scalar>>,
        ctx: &mut Context,
    ) {
        // first create a constant encryption of 0, then add the decomposed encoded value to it
        self.encrypt_constant_rgsw(out, &Plaintext(Scalar::zero()), ctx);
        let mut buf = PlaintextList::new(Scalar::zero(), ctx.plaintext_count());
        for (i, mut m) in out.0.as_mut_glwe_list().iter_mut().enumerate() {
            let level = (i / 2) + 1;
            let shift: usize = (Scalar::BITS as usize) - ctx.base_log.0 * level;
            buf.as_mut().copy_from_slice(encoded.as_ref());
            mul_const(buf.as_mut(), 1 << shift);
            if i % 2 == 0 {
                // in this case we're in the "top half" of the ciphertext

                // NOTE(abheet): modified!
                /*
                m.get_mut_mask()
                    .as_mut_polynomial_list()
                    .get_mut_polynomial(0)
                    .update_with_wrapping_add(&buf.as_polynomial());
                */

                if let Some(mut poly) = m.get_mut_mask().as_mut_polynomial_list()
                    .iter_mut().next() {
                    polynomial_wrapping_add_assign(&mut poly, &buf.as_polynomial());
                }
            } else {
                // this is the "bottom half"

                // NOTE(abheet): modified!
                /*
                m.get_mut_body()
                    .as_mut_polynomial()
                    .update_with_wrapping_add(&buf.as_polynomial());
                */

                polynomial_wrapping_add_assign(
                    &mut m.get_mut_body().as_mut_polynomial(),
                    &buf.as_polynomial()
                );
            }
        }
    }

    /// Create a vector of RGSW ciphertexts of a polynomial.
    pub fn encrypt_constant_rgsw_vec(
        &self,
        v: &[Plaintext<Scalar>],
        ctx: &mut Context,
    ) -> Vec<RGSWCiphertext> {
        v.iter()
            .map(|pt| {
                let mut rgsw_ct =
                    RGSWCiphertext::allocate(ctx.poly_size, ctx.base_log,
                        ctx.level_count, ctx.modulus);
                self.encrypt_constant_rgsw(&mut rgsw_ct, pt, ctx);
                rgsw_ct
            })
            .collect()
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    // NOTE(abheet): modified!
    /// Compute RGSW(-s), where s is self
    pub fn neg_gsw(&self, ctx: &mut Context) -> RGSWCiphertext {
        let neg_sk = {
            let mut pt = PlaintextList::new(Scalar::zero(), ctx.plaintext_count());
            for (x, y) in pt.as_mut().iter_mut().zip(self.0.as_ref().iter()) {
                *x = y * Scalar::MAX;
            }
            pt
        };
        // NOTE(abheet): takes the extra modulus parameter.
        let mut neg_sk_ct =
            RGSWCiphertext::allocate(ctx.poly_size, ctx.negs_base_log, 
                ctx.negs_level_count, ctx.modulus);
        self.encrypt_rgsw(&mut neg_sk_ct, &neg_sk, ctx);
        neg_sk_ct
    }
}

#[derive(Debug, Clone)]
/// An RLWE key switching key.
pub struct RLWEKeyswitchKey {
    ksks: Vec<RLWECiphertext>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    polynomial_size: PolynomialSize,
    subs_k: usize,

    // abheet: new field added!
    modulus: CiphertextModulus<Scalar>
}

impl RLWEKeyswitchKey {
    // NOTE(abheet): now it needs an extra argument of type CiphertextModulus.
    pub fn allocate(
        // TODO(abheet): what to do with all these fields?, are they compatible
        // with variable modulus.
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        polynomial_size: PolynomialSize,
        modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self {
            ksks: vec![
                RLWECiphertext::allocate(polynomial_size, modulus); decomp_level_count.0
            ],
            decomp_base_log,
            decomp_level_count,
            polynomial_size,
            subs_k: 0,
            modulus,
        }
    }

    pub const fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub const fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub const fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    // NOTE(abheet): modified!
    //
    /// Fill this object with the appropriate key switching key
    /// that is used for the substitution (subs) operation
    /// where `after_key` is s(X) and `before_key` is computed as s(X^k).
    pub fn fill_with_subs_keyswitch_key(
        &mut self,
        before_key: &mut RLWESecretKey,
        after_key: &RLWESecretKey,
        k: usize,
        // noise_parameters: impl DispersionParameter,
        noise_parameters: UniformBinary, // TODO(abheet): is this sound?
        generator: &mut EncryptionRandomGenerator<SoftwareRandomGenerator>,
    ) {
        // TODO reduce copy
        let poly_size = self.polynomial_size.0;
        let mut bar = after_key.0.as_polynomial_list();
        let mut fizz = &bar.as_ref()[(0 * poly_size)..(1 * poly_size)];
        let mut buzz = Polynomial::from_container(fizz);

        /*
        let before_poly = eval_x_k(
            &after_key.0.as_polynomial_list().get_polynomial(0),
            k
        );
        */

        let before_poly = eval_x_k(&buzz, k);
        before_key.fill_with_slice(before_poly.as_ref());
        self.fill_with_keyswitch_key(before_key, after_key, noise_parameters, generator);
        self.subs_k = k;
    }

    // TODO(abheet): modified!
    //
    /// Fill this object with the appropriate key switching key
    /// that transforms ciphertexts under `before_key` to ciphertexts under `after_key`.
    pub fn fill_with_keyswitch_key(
        &mut self,
        before_key: &RLWESecretKey,
        after_key: &RLWESecretKey,
        // noise_parameters: impl DispersionParameter,
        noise_parameters: UniformBinary, // TODO(abheet): is this sound?
        generator: &mut EncryptionRandomGenerator<SoftwareRandomGenerator>,
    ) {
        assert_eq!(before_key.0.as_polynomial_list().polynomial_count().0, 1);
        assert_eq!(after_key.0.as_polynomial_list().polynomial_count().0, 1);

        let mut buf =
            PlaintextList::new(Scalar::zero(), PlaintextCount(self.polynomial_size.0));

        // We retrieve decomposition arguments
        let decomp_level_count = self.decomp_level_count.0;
        let decomp_base_log = self.decomp_base_log.0;

        for (level, ksk) in (1..=decomp_level_count).zip(&mut self.ksks) {
            buf.as_mut().fill(Scalar::zero());
            buf.as_mut().copy_from_slice(before_key.0.as_ref());
            let shift: usize = (Scalar::BITS as usize) - decomp_base_log * level;
            mul_const(buf.as_mut(), 1 << shift);

            after_key.encrypt_rlwe_binary(ksk, &buf, noise_parameters, generator);
        }
        self.subs_k = 0;
    }

    /// Convert the key switching key into Fourier domain.
    pub fn into_fourier(self) -> FourierRLWEKeyswitchKey {
        // URGENT
        todo!();

        /*
        let fft = Fft::new(self.polynomial_size);
        let fft = fft.as_view();

        let mut mem = GlobalMemBuffer::new(
            fft.forward_scratch()
                .unwrap()
                .and(fft.backward_scratch().unwrap()),
        );

        let mut stack = DynStack::new(&mut mem);

        let fourier_vec = self
            .ksks
            .iter()
            .map(|ksk| {
                let mut fp_mask = FourierPolynomial {
                    data: vec![Complex::zero(); self.polynomial_size.0 / 2],
                };
                let mut fp_body = FourierPolynomial {
                    data: vec![Complex::zero(); self.polynomial_size.0 / 2],
                };
                fft.forward_as_torus(
                    unsafe { fp_mask.as_mut_view().into_uninit() },
                    ksk.get_mask().as_polynomial_list().get_polynomial(0),
                    stack.rb_mut(),
                );
                fft.forward_as_torus(
                    unsafe { fp_body.as_mut_view().into_uninit() },
                    ksk.get_body().as_polynomial(),
                    stack.rb_mut(),
                );
                FourierRLWECiphertext {
                    mask: fp_mask,
                    body: fp_body,
                }
            })
            .collect();
        FourierRLWEKeyswitchKey {
            ksks: fourier_vec,
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            polynomial_size: self.polynomial_size,
            subs_k: self.subs_k,
        }
        */
    }

    // NOTE(abheet): modified!
    //
    /// Run key switching.
    pub fn keyswitch_ciphertext(&self, after: &mut RLWECiphertext, before: &RLWECiphertext) {
        // clean the output ctxt and add c_1
        after.clear();

        // after
        //     .get_mut_body()
        //     .as_mut()
        //     .update_with_wrapping_add(before.get_body().as_tensor());
        slice_wrapping_add_assign(
            after.get_mut_body().as_mut(),
            before.get_body().as_ref()
        );

        let decomposer = SignedDecomposer::<Scalar>::new(self.decomp_base_log,
            self.decomp_level_count);
        // let mut rounded_mask = Tensor::allocate(Scalar::zero(), self.polynomial_size.0);
        let mut rounded_mask = vec![Scalar::zero(); self.polynomial_size.0];

        /*
        decomposer.fill_tensor_with_closest_representable(
            &mut rounded_mask,
            before.get_mask().as_tensor(),
        );
        */

        for (mask_, before_) in rounded_mask.iter_mut()
            .zip(before.get_mask().as_ref().iter()) {
            *mask_ = decomposer.closest_representable(*before_);
        }

        let mut decomposed_mask = decomposer.decompose_slice(&rounded_mask);

        // TODO reduce the temporary allocation
        let mut poly_mask = Polynomial::new(Scalar::zero(), self.polynomial_size);
        let mut poly_body = Polynomial::new(Scalar::zero(), self.polynomial_size);

        // Every chunk is a key switching key
        for ksk in self.ksks.iter().rev() {
            decomposed_mask.next_term().map_or_else(
                || {
                    panic!("no more next_term");
                },
                |term| {
                    assert_eq!(ksk.get_mask().as_polynomial_list().polynomial_count().0, 1);
                    poly_mask.as_mut().fill(Scalar::zero());
                    poly_body.as_mut().fill(Scalar::zero());

                    /*
                    fourier_update_with_mul_acc(
                        &mut poly_mask.as_mut_view(),
                        &ksk.get_mask().as_polynomial_list().get_polynomial(0),
                        &Polynomial::from_container(term.as_tensor().as_slice()),
                    );
                    */

                    fourier_update_with_mul_acc(
                        &mut poly_mask.as_mut_view(),
                        &ksk.get_mask().as_polynomial_list().iter().next().unwrap(),
                        &Polynomial::from_container(term.as_slice()),
                    );

                    fourier_update_with_mul_acc(
                        &mut poly_body.as_mut_view(),
                        &ksk.get_body().as_polynomial(),
                        &Polynomial::from_container(term.as_slice()),
                    );
                    after.update_mask_with_sub(&poly_mask.as_view());
                    after.update_body_with_sub(&poly_body.as_view());
                },
            );
        }
    }

    // NOTE(abheet): modified!
    /// The key switching key must be of the form s(X^k) to s(X),
    /// i.e., `fill_with_subs_keyswitch_key` must be called.
    pub fn subs(&self, after: &mut RLWECiphertext, before: &RLWECiphertext) {
        let k = self.subs_k;
        let mut c = RLWECiphertext::allocate(self.polynomial_size, self.modulus);
        c.0.as_mut().copy_from_slice(before.0.as_ref());

        // TODO reduce copying
        let c_mask_k = eval_x_k(
            &c.get_mask().as_polynomial_list().iter().next().unwrap(),
            k
        );
        let c_body_k = eval_x_k(&c.get_body().as_polynomial(), k);

        c.get_mut_mask()
            .as_mut()
            .copy_from_slice(c_mask_k.as_ref());
        c.get_mut_body()
            .as_mut()
            .copy_from_slice(c_body_k.as_ref());

        self.keyswitch_ciphertext(after, &c);
    }

    pub const fn get_keyswitch_key(&self) -> &Vec<RLWECiphertext> {
        &self.ksks
    }

    pub const fn get_subs_k(&self) -> usize {
        self.subs_k
    }
}

// NOTE(abheet): modified!, major modification.
#[derive(Debug, Clone)]
/// An RLWE ciphertext in the Fourier domain.
pub struct Fourier128RLWECiphertext {
    pub mask: Fourier128Polynomial<Vec<f64>>,
    pub body: Fourier128Polynomial<Vec<f64>>,

    // abheet: new field added!
    pub modulus: CiphertextModulus<Scalar>,
}

impl Fourier128RLWECiphertext {
    // NOTE(abheet): modified!
    pub fn new(poly_size: usize, modulus: CiphertextModulus<Scalar>) -> Self {
        // TODO(abheet): should the size be divided by 2 or 4?
        let fourier_size = poly_size / 2;
        Self {
            /*
            mask: FourierPolynomial {
                data: vec![Complex::zero(); poly_size / 2],
            },
            body: FourierPolynomial {
                data: vec![Complex::zero(); poly_size / 2],
            },
            */

            mask: Fourier128Polynomial {
                data_re0: vec![0.0; fourier_size],
                data_re1: vec![0.0; fourier_size],
                data_im0: vec![0.0; fourier_size],
                data_im1: vec![0.0; fourier_size],
            },

            body: Fourier128Polynomial {
                data_re0: vec![0.0; fourier_size],
                data_re1: vec![0.0; fourier_size],
                data_im0: vec![0.0; fourier_size],
                data_im1: vec![0.0; fourier_size],
            },


            modulus,
        }
    }

    // NOTE(abheet): add as needed! currently not being needed anywhere.
    //
    /*
    /// Convert the ciphertext back to standard domain.
    pub fn backward_as_torus(&mut self) -> RLWECiphertext {
        let p = self.body.polynomial_size();
        let fft = Fft128::new(p);
        let fft = fft.as_view();
        let mut out = RLWECiphertext::allocate(p, self.modulus);

        /*
        let mut mem = GlobalMemBuffer::new(
            fft.forward_scratch()
                .unwrap()
                .and(fft.backward_scratch().unwrap()),
        );

        let mut stack = DynStack::new(&mut mem);
        */

        /*
        fft.add_backward_as_torus(
            out.get_mut_mask()
                .as_mut_polynomial_list()
                .get_mut_polynomial(0),
            self.mask.as_view(),
            stack.rb_mut(),
        );
        fft.add_backward_as_torus(
            out.get_mut_body().as_mut_polynomial(),
            self.body.as_view(),
            stack.rb_mut(),
        );

        out
        */

        let mut buffer = PodBuffer::new(fft.backward_scratch());
        let mut stack = PodStack::new(&mut buffer);

        fft.backward_as_torus(
            out.get_mut_mask()
                .as_mut_polynomial_list()
                .iter_mut()
                .next()
                .unwrap()
                .as_mut(),

            &self.mask.data_re0,
            &self.mask.data_re1,
            &self.mask.data_im0,
            &self.mask.data_im1,

            &mut stack,
        );

        out
    }
    */
}

// NOTE(abheet): modified!
#[derive(Debug, Clone)]
/// An RLWE key switching key in the Fourier domain.
pub struct FourierRLWEKeyswitchKey {
    ksks: Vec<Fourier128RLWECiphertext>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    polynomial_size: PolynomialSize,
    subs_k: usize,

    // abheet: new field added!
    modulus: CiphertextModulus<Scalar>,
}

impl FourierRLWEKeyswitchKey {
    /// Perform key switching but don't convert the new ciphertext to the standard domain.
    pub fn keyswitch_ciphertext(&self, after: &mut Fourier128RLWECiphertext, before: &RLWECiphertext) {
        // URGENT
        todo!();

        /*
        let fft = Fft::new(self.polynomial_size);
        let fft = fft.as_view();

        let mut mem = GlobalMemBuffer::new(
            fft.forward_scratch()
                .unwrap()
                .and(fft.forward_scratch().unwrap())
                .and(fft.forward_scratch().unwrap())
                .and(fft.forward_scratch().unwrap())
                .and(fft.forward_scratch().unwrap())
                .and(fft.backward_scratch().unwrap()),
        );

        let mut stack = DynStack::new(&mut mem);

        let mut first_fourier = FourierPolynomial {
            data: vec![Complex::zero(); self.polynomial_size.0 / 2].into_boxed_slice(),
        };
        let mut second_fourier = FourierPolynomial {
            data: vec![Complex::zero(); self.polynomial_size.0 / 2].into_boxed_slice(),
        };

        fft.forward_as_torus(
            unsafe { first_fourier.as_mut_view().into_uninit() },
            before.get_mask().as_polynomial_list().get_polynomial(0),
            stack.rb_mut(),
        );
        fft.forward_as_torus(
            unsafe { second_fourier.as_mut_view().into_uninit() },
            before.get_body().as_polynomial(),
            stack.rb_mut(),
        );

        // clean the output ctxt and add c_1
        for c in after.mask.data.as_mut_slice().iter_mut() {
            *c = Complex::zero();
        }

        // TODO body.data is 2048 but fourier is 1024
        for (c, b) in izip!(&mut *after.body.data, &*second_fourier.data) {
            *c = *b;
        }

        // TODO the decomposer isn't an iterator so we need to make extra allocation
        let decomposer = SignedDecomposer::new(self.decomp_base_log, self.decomp_level_count);
        let mut rounded_mask = Tensor::allocate(Scalar::zero(), self.polynomial_size.0);
        decomposer.fill_tensor_with_closest_representable(
            &mut rounded_mask,
            before.get_mask().as_tensor(),
        );
        let mut decomposed_mask = decomposer.decompose_tensor(&rounded_mask);
        let mut terms = vec![];
        terms.reserve(self.decomp_level_count.0);
        for _ in 0..self.decomp_level_count.0 {
            decomposed_mask.next_term().map_or_else(
                || {
                    panic!("not enough terms");
                },
                |term| {
                    let term = Polynomial::from_container(
                        term.as_tensor()
                            .iter()
                            .map(|x| (0 as Scalar).wrapping_sub(*x))
                            .collect::<Vec<Scalar>>(),
                    );
                    terms.push(term);
                },
            );
        }

        let mut terms_iter = terms.iter();
        let mut ksk_iter = self.ksks.iter().rev();

        loop {
            match (ksk_iter.next(), ksk_iter.next()) {
                (Some(first), Some(second)) => {
                    let term1 = terms_iter.next().unwrap();
                    let term2 = terms_iter.next().unwrap();

                    fft.forward_as_integer(
                        unsafe { first_fourier.as_mut_view().into_uninit() },
                        term1.as_view(),
                        stack.rb_mut(),
                    );
                    fft.forward_as_integer(
                        unsafe { second_fourier.as_mut_view().into_uninit() },
                        term2.as_view(),
                        stack.rb_mut(),
                    );

                    pre_fourier_update_with_two_multiply_accumulate(
                        &mut after.mask.as_mut_view(),
                        &first.mask.as_view(),
                        &first_fourier.as_view(),
                        &second.mask.as_view(),
                        &second_fourier.as_view(),
                    );
                    pre_fourier_update_with_two_multiply_accumulate(
                        &mut after.body.as_mut_view(),
                        &first.body.as_view(),
                        &first_fourier.as_view(),
                        &second.body.as_view(),
                        &second_fourier.as_view(),
                    );
                }
                (Some(first), None) => {
                    let term1 = terms_iter.next().unwrap();

                    fft.forward_as_integer(
                        unsafe { first_fourier.as_mut_view().into_uninit() },
                        term1.as_view(),
                        stack.rb_mut(),
                    );

                    pre_fourier_update_with_multiply_accumulate(
                        &mut after.mask.as_mut_view(),
                        &first.mask.as_view(),
                        &first_fourier.as_view(),
                    );

                    pre_fourier_update_with_multiply_accumulate(
                        &mut after.body.as_mut_view(),
                        &first.body.as_view(),
                        &first_fourier.as_view(),
                    );
                }
                _ => break,
            }
        }
        */
    }

    // NOTE(abheet): modified!
    /// Perform the substitution operation that converts RLWE(p(X)) to RLWE(p(X^k)).
    /// The key switching key must be of the form s(X^k) to s(X).
    pub fn subs(&self, after: &mut Fourier128RLWECiphertext, before: &RLWECiphertext) {
        let k = self.subs_k;
        let mut c = RLWECiphertext::allocate(self.polynomial_size, self.modulus);
        c.0.as_mut().copy_from_slice(before.0.as_ref());

        // TODO reduce copying
        let c_mask_k = eval_x_k(
            &c.get_mask().as_polynomial_list().iter().next().unwrap(),
            k
        );
        let c_body_k = eval_x_k(&c.get_body().as_polynomial(), k);
        c.get_mut_mask()
            .as_mut()
            .copy_from_slice(c_mask_k.as_ref());
        c.get_mut_body()
            .as_mut()
            .copy_from_slice(c_body_k.as_ref());

        self.keyswitch_ciphertext(after, &c);
    }

    pub const fn get_subs_k(&self) -> usize {
        self.subs_k
    }
}

// NOTE(abheet): modified!
/// Generate all the key switching keys needed for the substitution operation.
pub fn gen_all_subs_ksk(
    after_key: &RLWESecretKey,
    ctx: &mut Context,
) -> HashMap<usize, RLWEKeyswitchKey> {
    let mut hm = HashMap::new();
    let poly_size = ctx.poly_size;
    let mut dummy_sk = RLWESecretKey::zero(poly_size);
    for i in 1..=log2(poly_size.0) {
        let k = poly_size.0 / (1 << (i - 1)) + 1;

        // takes extra modulus argument.
        let mut ksk = RLWEKeyswitchKey::allocate(ctx.ks_base_log, ctx.ks_level_count,
            poly_size, ctx.modulus);
        ksk.fill_with_subs_keyswitch_key(
            &mut dummy_sk,
            after_key,
            k,
            // ctx.std,
            // TODO(abheet): is it correct?
            UniformBinary,
            &mut ctx.encryption_generator,
        );
        hm.insert(k, ksk);
    }
    hm
}

// NOTE(abheet): modified!
/// Generate all the key switching keys needed for the substitution operation
/// in the Fourier domain.
pub fn gen_all_subs_ksk_fourier(
    after_key: &RLWESecretKey,
    ctx: &mut Context,
) -> HashMap<usize, FourierRLWEKeyswitchKey> {
    let poly_size = ctx.poly_size;
    let mut hm = HashMap::new();
    let mut dummy_sk = RLWESecretKey::zero(poly_size);
    for i in 1..=log2(poly_size.0) {
        let k = poly_size.0 / (1 << (i - 1)) + 1;
        
        // takes extra modulus argument.
        let mut ksk = RLWEKeyswitchKey::allocate(ctx.ks_base_log, ctx.ks_level_count,
            poly_size, ctx.modulus);
        ksk.fill_with_subs_keyswitch_key(
            &mut dummy_sk,
            after_key,
            k,
            // ctx.std,
            // TODO(abheet): is it correct?
            UniformBinary,
            &mut ctx.encryption_generator,
        );
        hm.insert(k, ksk.into_fourier());
    }
    hm
}

// NOTE(abheet): modified!
/// Expand/convert RLWE ciphertexts to an RGSW ciphertext.
/// The number of RLWE ciphertexts is defined by the decomposition level.
pub fn expand(
    cs: &[RLWECiphertext],
    ksk_map: &HashMap<usize, RLWEKeyswitchKey>,
    neg_s: &RGSWCiphertext,
    ctx: &Context,
) -> RGSWCiphertext {
    let mut buf = FftBuffer::new(cs[0].polynomial_size());
    let cs_prime: Vec<RLWECiphertext> = cs.iter().map(|c| c.trace1(ksk_map)).collect();

    // takes extra modulus argument.
    let mut out = RGSWCiphertext::allocate(ctx.poly_size, ctx.base_log, ctx.level_count, 
        ctx.modulus);
    for (i, mut c) in out.0.as_mut_glwe_list().iter_mut().enumerate() {
        let k = i / 2;
        if i % 2 == 0 {
            neg_s.external_product_with_buf_glwe(&mut c, &cs_prime[k], &mut buf);
        } else {
            c.as_mut().copy_from_slice(cs_prime[k].0.as_ref());
        }
    }
    out
}

// NOTE(abheet): modified!
/// Same as expand but using key switching keys in the Fourier domain.
#[allow(clippy::ptr_arg)]
pub fn expand_fourier(
    cs: &Vec<RLWECiphertext>,
    ksk_map: &HashMap<usize, FourierRLWEKeyswitchKey>,
    neg_s: &RGSWCiphertext,
    ctx: &Context,
) -> RGSWCiphertext {
    let mut buf = FftBuffer::new(cs[0].polynomial_size());
    // takes extra modulus argument.
    let mut out = RGSWCiphertext::allocate(ctx.poly_size, ctx.base_log, 
        ctx.level_count, ctx.modulus);

    // takes extra modulus argument.
    let mut c_prime = RLWECiphertext::allocate(ctx.poly_size, ctx.modulus);
    for (i, mut c) in out.0.as_mut_glwe_list().iter_mut().enumerate() {
        let k = i / 2;
        if i % 2 == 0 {
            cs[k].trace1_fourier(&mut c_prime, ksk_map);
            neg_s.external_product_with_buf_glwe(&mut c, &c_prime, &mut buf);
        } else {
            c.as_mut().copy_from_slice(c_prime.0.as_ref());
        }
    }
    out
}

// NOTE(abheet): commented out because nothing is currently using it.
//
/*
/// Use the slower method to convert a set of scaled RLWE ciphertext
/// into a RGSW ciphertext, this operation takes O(N^2) where
/// N is the degree of the polynomial.
pub fn expand_slow(
    cs: &Vec<RLWECiphertext>,
    ksks: &LWEtoRLWEKeyswitchKey,
    neg_s: &RGSWCiphertext,
    ctx: &Context,
) -> RGSWCiphertext {
    assert_eq!(ctx.poly_size.0, ksks.inner.len());
    assert_eq!(cs.len(), ctx.level_count.0);

    let mut buf = FftBuffer::new(cs[0].polynomial_size());
    let rlwe_cts: Vec<RLWECiphertext> = cs
        .iter()
        .map(|c| {
            // TODO reduce allocation
            let mut lwe = LWECiphertext::allocate(ctx.lwe_size());
            lwe.fill_with_const_sample_extract(c);
            // new rlwe below
            conv_lwe_to_rlwe(ksks, &lwe, ctx)
        })
        .collect();

    decomposed_rlwe_to_rgsw(&rlwe_cts, neg_s, ctx, &mut buf)
}
*/

// NOTE(abheet): modified!
pub fn decomposed_rlwe_to_rgsw(
    cs: &[RLWECiphertext],
    neg_s: &RGSWCiphertext,
    ctx: &Context,
    buf: &mut FftBuffer,
) -> RGSWCiphertext {
    // takes extra modulus argument.
    let mut out = RGSWCiphertext::allocate(ctx.poly_size, ctx.base_log, 
        ctx.level_count, ctx.modulus);
    for (i, mut c) in out.0.as_mut_glwe_list().iter_mut().enumerate() {
        let k = i / 2;
        if i % 2 == 0 {
            neg_s.external_product_with_buf_glwe(&mut c, &cs[k], buf);
        } else {
            c.as_mut().copy_from_slice(cs[k].0.as_ref());
        }
    }
    out
}

// NOTE(abheet): modified!
//
/*
fn fourier_update_with_mul(p1: &mut Polynomial<&mut [Scalar]>, p2: &Polynomial<&[Scalar]>) {
    let fft = Fft::new(p1.polynomial_size());
    let fft = fft.as_view();

    let mut mem = GlobalMemBuffer::new(
        fft.forward_scratch()
            .unwrap()
            .and(fft.backward_scratch().unwrap()),
    );

    let mut stack = DynStack::new(&mut mem);

    let mut fp1 = FourierPolynomial {
        data: vec![Complex::zero(); p1.polynomial_size().0 / 2].into_boxed_slice(),
    };
    let mut fp2 = FourierPolynomial {
        data: vec![Complex::zero(); p2.polynomial_size().0 / 2].into_boxed_slice(),
    };

    fft.forward_as_torus(
        unsafe { fp1.as_mut_view().into_uninit() },
        p1.as_view(),
        stack.rb_mut(),
    );
    fft.forward_as_integer(
        unsafe { fp2.as_mut_view().into_uninit() },
        p2.as_view(),
        stack.rb_mut(),
    );

    for (f0, f1) in izip!(&mut *fp1.data, &*fp2.data) {
        *f0 *= *f1;
    }

    fft.backward_as_torus(
        unsafe { p1.as_mut_view().into_uninit() },
        fp1.as_view(),
        stack,
    );
}
*/

// /*
// TODO(abheet): is this correct? WRONG! - apurba: seems to work after my scratch_buffer fix
fn fourier_update_with_mul(p1: &mut Polynomial<&mut [Scalar]>, p2: &Polynomial<&[Scalar]>) {
    let fft = Fft128::new(p1.polynomial_size());
    let fft = fft.as_view();

    let n = p1.polynomial_size().0 / 2;

    let mut fp1_re0 = vec![0.0f64; n];
    let mut fp1_re1 = vec![0.0f64; n];
    let mut fp1_im0 = vec![0.0f64; n];
    let mut fp1_im1 = vec![0.0f64; n];

    fft.forward_as_torus(
        &mut fp1_re0,
        &mut fp1_re1,
        &mut fp1_im0,
        &mut fp1_im1,
        p1.as_view().as_ref(),
    );

    let mut fp2_re0 = vec![0.0f64; n];
    let mut fp2_re1 = vec![0.0f64; n];
    let mut fp2_im0 = vec![0.0f64; n];
    let mut fp2_im1 = vec![0.0f64; n];

    fft.forward_as_integer(
        &mut fp2_re0,
        &mut fp2_re1,
        &mut fp2_im0,
        &mut fp2_im1,
        p2.as_view().as_ref(),
    );

    for i in 0..n {
        let a0 = fp1_re0[i];
        let b0 = fp1_im0[i];
        let c0 = fp2_re0[i];
        let d0 = fp2_im0[i];

        fp1_re0[i] = a0 * c0 - b0 * d0;
        fp1_im0[i] = a0 * d0 + b0 * c0;

        let a1 = fp1_re1[i];
        let b1 = fp1_im1[i];
        let c1 = fp2_re1[i];
        let d1 = fp2_im1[i];

        fp1_re1[i] = a1 * c1 - b1 * d1;
        fp1_im1[i] = a1 * d1 + b1 * c1;
    }

    // let mut scratch = vec![0u8; 4 * n * size_of::<f64>()];
    // let mut stack = dyn_stack::PodStack::new(&mut scratch);

    // apurba
    let mut scratch_buffer = dyn_stack::PodBuffer::new(fft.backward_scratch());
    let mut stack = dyn_stack::PodStack::new(&mut scratch_buffer);

    fft.backward_as_torus(
        p1.as_mut_view().as_mut(),
        &fp1_re0,
        &fp1_re1,
        &fp1_im0,
        &fp1_im1,
        &mut stack
    );
}
// */

// apurba - debug
// fn fourier_update_with_mul(p1: &mut Polynomial<&mut [Scalar]>, p2: &Polynomial<&[Scalar]>) {
//     let mut tmp = Polynomial::new(Scalar::zero(), p1.polynomial_size());
//     polynomial_wrapping_mul(&mut tmp, &p1.as_view(), p2);   // exact mod X^N + 1
//     p1.as_mut().copy_from_slice(tmp.as_ref());
// }

// NOTE(abheet): modified!
//
/*
fn fourier_update_with_mul_acc(
    out: &mut Polynomial<&mut [Scalar]>,
    p1: &Polynomial<&[Scalar]>,
    p2: &Polynomial<&[Scalar]>,
) {
    let fft = Fft::new(p1.polynomial_size());
    let fft = fft.as_view();

    let mut mem = GlobalMemBuffer::new(
        fft.forward_scratch()
            .unwrap()
            .and(fft.backward_scratch().unwrap()),
    );

    let mut stack = DynStack::new(&mut mem);

    let mut fp1 = FourierPolynomial {
        data: vec![Complex::zero(); p1.polynomial_size().0 / 2].into_boxed_slice(),
    };
    let mut fp2 = FourierPolynomial {
        data: vec![Complex::zero(); p2.polynomial_size().0 / 2].into_boxed_slice(),
    };

    fft.forward_as_torus(
        unsafe { fp1.as_mut_view().into_uninit() },
        p1.as_view(),
        stack.rb_mut(),
    );
    fft.forward_as_integer(
        unsafe { fp2.as_mut_view().into_uninit() },
        p2.as_view(),
        stack.rb_mut(),
    );

    for (f0, f1) in izip!(&mut *fp1.data, &*fp2.data) {
        *f0 *= *f1;
    }

    fft.add_backward_as_torus(out.as_mut_view(), fp1.as_view(), stack);
}
*/

// /*
// TODO(abheet): is this correct? WRONG! - apurba: haven't verified this yet, might work since fourier_update_with_mul is working
fn fourier_update_with_mul_acc(
    out: &mut Polynomial<&mut [Scalar]>,
    p1: &Polynomial<&[Scalar]>,
    p2: &Polynomial<&[Scalar]>,
) {
    let fft = Fft128::new(p1.polynomial_size());
    let fft = fft.as_view();

    let n = p1.polynomial_size().0 / 2;

    let mut p1_re0 = vec![0.0; n];
    let mut p1_re1 = vec![0.0; n];
    let mut p1_im0 = vec![0.0; n];
    let mut p1_im1 = vec![0.0; n];

    let mut p2_re0 = vec![0.0; n];
    let mut p2_re1 = vec![0.0; n];
    let mut p2_im0 = vec![0.0; n];
    let mut p2_im1 = vec![0.0; n];

    fft.forward_as_torus(
        &mut p1_re0,
        &mut p1_re1,
        &mut p1_im0,
        &mut p1_im1,
        p1.as_view().as_ref(),
    );

    fft.forward_as_integer(
        &mut p2_re0,
        &mut p2_re1,
        &mut p2_im0,
        &mut p2_im1,
        p2.as_view().as_ref(),
    );

    for i in 0..n {
        let a0r = p1_re0[i];
        let a0i = p1_im0[i];
        let b0r = p2_re0[i];
        let b0i = p2_im0[i];

        p1_re0[i] = a0r * b0r - a0i * b0i;
        p1_im0[i] = a0r * b0i + a0i * b0r;

        let a1r = p1_re1[i];
        let a1i = p1_im1[i];
        let b1r = p2_re1[i];
        let b1i = p2_im1[i];

        p1_re1[i] = a1r * b1r - a1i * b1i;
        p1_im1[i] = a1r * b1i + a1i * b1r;
    }

    // let mut scratch = vec![0u8; 4 * n * size_of::<f64>()];
    // let mut stack = dyn_stack::PodStack::new(&mut scratch);

    // apurba
    let mut scratch_buffer = dyn_stack::PodBuffer::new(fft.backward_scratch());
    let mut stack = dyn_stack::PodStack::new(&mut scratch_buffer);

    fft.add_backward_as_torus(
        out.as_mut(),
        &p1_re0,
        &p1_re1,
        &p1_im0,
        &p1_im1,
        stack,
    );
}
// */

// apurba - debug
// fn fourier_update_with_mul_acc(
//     out: &mut Polynomial<&mut [Scalar]>,
//     p1: &Polynomial<&[Scalar]>,
//     p2: &Polynomial<&[Scalar]>,
// ) {
//     let mut tmp = Polynomial::new(Scalar::zero(), p1.polynomial_size());
//     polynomial_wrapping_mul(&mut tmp, p1, p2);
//     polynomial_wrapping_add_assign(out, &tmp);   // out += p1 * p2
// }

fn pre_fourier_update_with_multiply_accumulate(
    out: &mut FourierPolynomial<&mut [Complex]>,
    fp1: &FourierPolynomial<&[Complex]>,
    fp2: &FourierPolynomial<&[Complex]>,
) {
    for (o, f1, f2) in izip!(&mut *out.data, fp1.data, fp2.data) {
        *o += *f1 * *f2;
    }
}

fn pre_fourier_update_with_two_multiply_accumulate(
    out: &mut FourierPolynomial<&mut [Complex]>,
    fp1: &FourierPolynomial<&[Complex]>,
    fp2: &FourierPolynomial<&[Complex]>,
    fp3: &FourierPolynomial<&[Complex]>,
    fp4: &FourierPolynomial<&[Complex]>,
) {
    for (o, f1, f2, f3, f4) in izip!(&mut *out.data, fp1.data, fp2.data, fp3.data, fp4.data) {
        *o += (*f1 * *f2) + (*f3 * *f4);
    }
}

// NOTE(abheet): modified!
//
pub fn naive_update_with_mul_acc<M, C>(
    out: &mut Polynomial<M>,
    p1: &Polynomial<C>,
    p2: &Polynomial<C>,
) where
    // C: AsRefSlice<Element = Scalar>,
    // M: AsMutSlice<Element = Scalar>,
    C: Container<Element = Scalar>,
    M: ContainerMut<Element = Scalar>,
{
    polynomial_wrapping_add_mul_assign(out, p1, p2);
}

// NOTE(abheet): modified!
//
pub fn naive_update_with_mul<M, C>(p1: &mut Polynomial<M>, p2: &Polynomial<C>)
where
    C: Container<Element = Scalar>,
    M: ContainerMut<Element = Scalar>,
{
    let mut tmp = Polynomial::new(Scalar::zero(), p1.polynomial_size());
    polynomial_wrapping_mul(&mut tmp, p1, p2);
    p1.as_mut().copy_from_slice(tmp.as_ref());
}


// NOTE(abheet): these two functions were not being used by anything.
//
/*
/// Create RLWE ciphertexts that are suitable to be used by expand.
pub fn make_decomposed_rlwe_ct(
    sk: &RLWESecretKey,
    bit: Scalar,
    ctx: &mut Context,
) -> Vec<RLWECiphertext> {
    assert!(bit == Scalar::one() || bit == Scalar::zero());
    let logn = log2(ctx.poly_size.0);
    let out = (1..=ctx.level_count.0).map(|level| {
        assert!(ctx.base_log.0 * level + logn <= Scalar::BITS as usize);
        let shift: usize = (Scalar::BITS as usize) - ctx.base_log.0 * level - logn;
        let ptxt = {
            let mut p = ctx.gen_ternary_ptxt();
            *p.as_mut_polynomial()
                .get_mut_monomial(MonomialDegree(0))
                .get_mut_coefficient() = bit << shift;
            p
        };
        let mut ct = RLWECiphertext::allocate(ctx.poly_size);
        sk.encrypt_rlwe(&mut ct, &ptxt, ctx.std, &mut ctx.encryption_generator);
        ct
    });
    out.collect()
}

/// Create RLWE ciphertexts that are suitable to be used by `expand_slow`.
/// It does not have the - logn term in the shift.
pub fn make_decomposed_rlwe_ct2(
    sk: &RLWESecretKey,
    bit: Scalar,
    ctx: &mut Context,
) -> Vec<RLWECiphertext> {
    assert!(bit == Scalar::one() || bit == Scalar::zero());
    let out = (1..=ctx.level_count.0).map(|level| {
        let shift: usize = (Scalar::BITS as usize) - ctx.base_log.0 * level;
        let ptxt = {
            let mut p = ctx.gen_ternary_ptxt();
            *p.as_mut_polynomial()
                .get_mut_monomial(MonomialDegree(0))
                .get_mut_coefficient() = bit << shift;
            p
        };
        let mut ct = RLWECiphertext::allocate(ctx.poly_size);
        sk.encrypt_rlwe(&mut ct, &ptxt, ctx.std, &mut ctx.encryption_generator);
        ct
    });
    out.collect()
}
*/

// NOTE(abheet): modified!
//
/// Compute the noise for ciphertext `ct`
/// given the (possibly encoded) plaintext `ptxt`.
pub fn compute_noise<C>(
    sk: &RLWESecretKey,
    ct: &RLWECiphertext,
    encoded_ptxt: &PlaintextList<C>,
) -> f64
where
    C: Container<Element = Scalar>,
{
    // pt = b - a*s = Delta*m + e
    let mut pt = PlaintextList::new(Scalar::zero(), encoded_ptxt.plaintext_count());
    sk.decrypt_rlwe(&mut pt, ct);

    // pt = pt - Delta*m = e (encoded_ptxt is Delta*m)
    polynomial_wrapping_sub_assign(&mut pt.as_mut_polynomial(), 
        &encoded_ptxt.as_polynomial());

    let mut max_e: SignedScalar = 0;
    for x in pt.as_ref().iter() {
        // convert x to signed
        let z = (*x as SignedScalar).abs();
        if z > max_e {
            max_e = z;
        }
    }
    (max_e as f64).log2()
}

// NOTE(abheet): modified!
// Does not uses tensor api now.
//
pub fn compute_noise_ternary<C>(
    sk: &RLWESecretKey,
    ct: &RLWECiphertext,
    ptxt: &PlaintextList<C>,
) -> f64
where
    C: Container<Element = Scalar>,
{
    let mut tmp = PlaintextList::new(Scalar::zero(), ptxt.plaintext_count());
    tmp.as_mut().copy_from_slice(ptxt.as_ref());
    Codec::poly_ternary_decode(&mut tmp.as_mut_polynomial());
    compute_noise(sk, ct, &tmp)
}

// NOTE(abheet): modified!
// Does not uses tensor api now.
//
/// Compute the noise for ciphertext `ct`
/// given the unencoded plaintext `ptxt`.
/// So the codec must be given.
pub fn compute_noise_encoded<C>( // NEEDED
    sk: &RLWESecretKey,
    ct: &RLWECiphertext,
    ptxt: &PlaintextList<C>,
    codec: &Codec,
) -> f64
where
    C: Container<Element = Scalar>,
{
    let mut tmp = PlaintextList::new(Scalar::zero(), ptxt.plaintext_count());
    tmp.as_mut().copy_from_slice(ptxt.as_ref());
    codec.poly_encode(&mut tmp.as_mut_polynomial());
    compute_noise(sk, ct, &tmp)
}

// NOTE(abheet): tests have not been migrated yet, DO NOT RUN the tests.
#[cfg(test)]
mod test {

    use crate::params::TFHEParameters;
    use crate::rgsw::compute_noise_rgsw1;

    use super::*;
    use concrete_core::{commons::math::tensor::AsRefTensor, prelude::LogStandardDev};

    #[test]
    fn test_keyswitching() {
        let mut ctx = Context::new(TFHEParameters::default());
        let messages = ctx.gen_ternary_ptxt();

        let sk_after = ctx.gen_rlwe_sk();
        let sk_before = ctx.gen_rlwe_sk();

        let mut ct_after = RLWECiphertext::allocate(ctx.poly_size);
        let mut ct_before = RLWECiphertext::allocate(ctx.poly_size);

        let mut ksk =
            RLWEKeyswitchKey::allocate(ctx.ks_base_log, ctx.ks_level_count, ctx.poly_size);
        ksk.fill_with_keyswitch_key(
            &sk_before,
            &sk_after,
            ctx.std,
            &mut ctx.encryption_generator,
        );

        // encrypts with the before key our messages
        sk_before.ternary_encrypt_rlwe(&mut ct_before, &messages, &mut ctx);
        // println!("msg before: {:?}", messages.as_tensor());
        let mut dec_messages_1 = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        sk_before.ternary_decrypt_rlwe(&mut dec_messages_1, &ct_before);
        // println!("msg after dec: {:?}", dec_messages_1.as_tensor());
        println!(
            "initial noise: {:?}",
            compute_noise_ternary(&sk_before, &ct_before, &messages)
        );

        ksk.keyswitch_ciphertext(&mut ct_after, &ct_before);

        let mut dec_messages_2 = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        sk_after.ternary_decrypt_rlwe(&mut dec_messages_2, &ct_after);
        // println!("msg after ks: {:?}", dec_messages_2.as_tensor());

        assert_eq!(dec_messages_1, dec_messages_2);
        assert_eq!(dec_messages_1, messages);
        println!(
            "final noise: {:?}",
            compute_noise_ternary(&sk_after, &ct_after, &messages)
        );
    }

    #[test]
    fn test_keyswitching_fourier() {
        let mut ctx = Context::new(TFHEParameters::default());
        let messages = ctx.gen_ternary_ptxt();

        let sk_after = ctx.gen_rlwe_sk();
        let sk_before = ctx.gen_rlwe_sk();

        let mut ct_after_fourier = FourierRLWECiphertext::new(ctx.poly_size.0);
        let mut ct_before = RLWECiphertext::allocate(ctx.poly_size);

        let mut ksk =
            RLWEKeyswitchKey::allocate(ctx.ks_base_log, ctx.ks_level_count, ctx.poly_size);
        ksk.fill_with_keyswitch_key(
            &sk_before,
            &sk_after,
            ctx.std,
            &mut ctx.encryption_generator,
        );
        // let mut buffers = FourierBuffers::new(ctx.poly_size, GlweSize(2));
        let ksk_fourier = ksk.into_fourier();

        // encrypts with the before key our messages
        sk_before.ternary_encrypt_rlwe(&mut ct_before, &messages, &mut ctx);
        // println!("msg before: {:?}", messages.as_tensor());
        let mut dec_messages_1 = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        sk_before.ternary_decrypt_rlwe(&mut dec_messages_1, &ct_before);
        // println!("msg after dec: {:?}", dec_messages_1.as_tensor());
        println!(
            "initial noise: {:?}",
            compute_noise_ternary(&sk_before, &ct_before, &messages)
        );

        ksk_fourier.keyswitch_ciphertext(&mut ct_after_fourier, &ct_before);
        let ct_after = ct_after_fourier.backward_as_torus();

        let mut dec_messages_2 = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        sk_after.ternary_decrypt_rlwe(&mut dec_messages_2, &ct_after);
        // println!("msg after ks: {:?}", dec_messages_2.as_tensor());

        assert_eq!(dec_messages_1, dec_messages_2);
        assert_eq!(dec_messages_1, messages);
        println!(
            "final noise: {:?}",
            compute_noise_ternary(&sk_after, &ct_after, &messages)
        );
    }

    #[test]
    fn test_subs() {
        let mut ctx = Context::new(TFHEParameters::default());
        let messages = ctx.gen_ternary_ptxt();
        let k = ctx.poly_size.0 + 1;

        let sk_after = ctx.gen_rlwe_sk();
        let mut sk_before = ctx.gen_rlwe_sk();

        let mut ct_after = RLWECiphertext::allocate(ctx.poly_size);
        let mut ct_before = RLWECiphertext::allocate(ctx.poly_size);

        let mut ksk =
            RLWEKeyswitchKey::allocate(ctx.ks_base_log, ctx.ks_level_count, ctx.poly_size);
        ksk.fill_with_subs_keyswitch_key(
            &mut sk_before,
            &sk_after,
            k,
            ctx.std,
            &mut ctx.encryption_generator,
        );

        // encrypt the message using the after key, put it in ct_before
        sk_after.ternary_encrypt_rlwe(&mut ct_before, &messages, &mut ctx);
        ksk.subs(&mut ct_after, &ct_before);

        let mut decrypted = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        sk_after.ternary_decrypt_rlwe(&mut decrypted, &ct_after);

        let mut expected = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        expected
            .as_mut_tensor()
            .fill_with_copy(eval_x_k(&messages.as_polynomial(), k).as_tensor());
        println!("msg after ks: {:?}", decrypted.as_tensor());
        println!("expected msg: {:?}", expected.as_tensor());
        assert_eq!(decrypted, expected);
    }

    #[test]
    fn test_subs_fourier() {
        let mut ctx = Context::new(TFHEParameters::default());
        let messages = ctx.gen_ternary_ptxt();
        let k = ctx.poly_size.0 + 1;

        let sk_after = ctx.gen_rlwe_sk();
        let mut sk_before = ctx.gen_rlwe_sk();

        let mut ct_after_fourier = FourierRLWECiphertext::new(ctx.poly_size.0);
        let mut ct_before = RLWECiphertext::allocate(ctx.poly_size);

        let mut ksk =
            RLWEKeyswitchKey::allocate(ctx.ks_base_log, ctx.ks_level_count, ctx.poly_size);
        ksk.fill_with_subs_keyswitch_key(
            &mut sk_before,
            &sk_after,
            k,
            ctx.std,
            &mut ctx.encryption_generator,
        );
        // let mut buffers = FourierBuffers::new(ctx.poly_size, GlweSize(2));
        let ksk_fourier = ksk.into_fourier();

        // encrypt the message using the after key, put it in ct_before
        sk_after.ternary_encrypt_rlwe(&mut ct_before, &messages, &mut ctx);
        ksk_fourier.subs(&mut ct_after_fourier, &ct_before);
        let ct_after = ct_after_fourier.backward_as_torus();

        let mut decrypted = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        sk_after.ternary_decrypt_rlwe(&mut decrypted, &ct_after);

        let mut expected = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        expected
            .as_mut_tensor()
            .fill_with_copy(eval_x_k(&messages.as_polynomial(), k).as_tensor());
        println!("msg after ks: {:?}", decrypted.as_tensor());
        println!("expected msg: {:?}", expected.as_tensor());
        assert_eq!(decrypted, expected);
    }

    #[test]
    fn test_eval_poly() {
        let neg_one = Scalar::MAX;
        let neg_two = neg_one - 1;
        let neg_three = neg_one - 2;
        let poly = Polynomial::from_container(vec![0, 1, 2, 3]);
        {
            let out = eval_x_k(&poly, 3);
            let expected = Polynomial::from_container(vec![0, 3, neg_two, 1]);
            assert_eq!(out, expected);
        }
        {
            let out = eval_x_k(&poly, 5);
            let expected = Polynomial::from_container(vec![0, neg_one, 2, neg_three]);
            assert_eq!(out, expected);
        }
    }

    #[test]
    fn test_trace1() {
        let mut ctx = Context::new(TFHEParameters::default());

        let orig_msg = ctx.gen_binary_pt();
        // println!("ptxt before: {:?}", orig_msg);
        let mut encoded_msg = orig_msg.clone();
        ctx.codec.poly_encode(&mut encoded_msg.as_mut_polynomial());
        // we need to divide the encoded message by n, because n is multiplied into the trace output
        for coeff in encoded_msg.as_mut_polynomial().coefficient_iter_mut() {
            *coeff /= ctx.poly_size.0 as Scalar;
        }

        let sk = RLWESecretKey::generate_binary(ctx.poly_size, &mut ctx.secret_generator);
        let mut ct = RLWECiphertext::allocate(ctx.poly_size);

        let all_ksk = gen_all_subs_ksk(&sk, &mut ctx);

        sk.encrypt_rlwe(
            &mut ct,
            &encoded_msg,
            ctx.std,
            &mut ctx.encryption_generator,
        );
        println!("initial noise: {:?}", compute_noise(&sk, &ct, &encoded_msg));

        let out = ct.trace1(&all_ksk);

        let mut decrypted = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        sk.decrypt_decode_rlwe(&mut decrypted, &out, &ctx);

        // println!("ptxt after: {:?}", decrypted);

        let expected = {
            let mut tmp = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            *tmp.as_mut_polynomial()
                .get_mut_monomial(MonomialDegree(0))
                .get_mut_coefficient() = *orig_msg
                .as_polynomial()
                .get_monomial(MonomialDegree(0))
                .get_coefficient();
            tmp
        };
        println!(
            "final noise: {:?}",
            compute_noise_encoded(&sk, &out, &expected, &ctx.codec)
        );
        assert_eq!(decrypted, expected);
    }

    #[test]
    fn test_binary_enc() {
        let mut ctx = Context::new(TFHEParameters::default());
        let ptxt_expected = ctx.gen_binary_pt();

        let sk = ctx.gen_rlwe_sk();
        let mut ct = RLWECiphertext::allocate(ctx.poly_size);
        sk.encode_encrypt_rlwe(&mut ct, &ptxt_expected, &mut ctx);

        let mut ptxt_actual = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        sk.decrypt_decode_rlwe(&mut ptxt_actual, &ct, &ctx);

        assert_eq!(ptxt_actual, ptxt_expected);
    }

    #[test]
    fn test_ternary_enc() {
        let mut ctx = Context::new(TFHEParameters::default());
        let ptxt_expected = ctx.gen_ternary_ptxt();

        let sk = ctx.gen_rlwe_sk();
        let mut ct = RLWECiphertext::allocate(ctx.poly_size);
        sk.ternary_encrypt_rlwe(&mut ct, &ptxt_expected, &mut ctx);

        let mut ptxt_actual = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        sk.ternary_decrypt_rlwe(&mut ptxt_actual, &ct);

        assert_eq!(ptxt_actual, ptxt_expected);
    }

    #[test]
    fn test_encrypt_rgsw() {
        let mut ctx = Context::new(TFHEParameters::default());
        let gsw_pt = ctx.gen_binary_pt();
        let one_pt = ctx.gen_unit_pt();

        let sk = ctx.gen_rlwe_sk();
        let mut gsw_ct = RGSWCiphertext::allocate(ctx.poly_size, ctx.base_log, ctx.level_count);
        let mut lwe_ct = RLWECiphertext::allocate(ctx.poly_size);

        sk.encrypt_rgsw(&mut gsw_ct, &gsw_pt, &mut ctx);
        sk.encode_encrypt_rlwe(&mut lwe_ct, &one_pt, &mut ctx);
        println!(
            "initial noise: {:?}",
            compute_noise_encoded(&sk, &lwe_ct, &one_pt, &ctx.codec)
        );

        {
            // check the first row of the RGSW ciphertext
            // the first row should have the form (a + m*(q/B), a*s + e),
            // so we subtract m*(q/B) and then check the noise
            let mut pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            pt.as_mut_tensor().fill_with_copy(gsw_pt.as_tensor());
            let shift: usize = (Scalar::BITS as usize) - ctx.base_log.0;
            mul_const(pt.as_mut_tensor(), 1 << shift);

            let mut row_ct = gsw_ct.get_nth_row(0);
            row_ct
                .get_mut_mask()
                .as_mut_polynomial_list()
                .get_mut_polynomial(0)
                .update_with_wrapping_sub(&pt.as_polynomial());
            println!(
                "first row noise: {:?}",
                compute_noise(&sk, &row_ct, &ctx.gen_zero_pt())
            );
        }
        {
            // check the second row of the RGSW ciphertext
            let row_ct = gsw_ct.get_nth_row(1);
            let mut pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            pt.as_mut_tensor().fill_with_copy(gsw_pt.as_tensor());
            let shift: usize = (Scalar::BITS as usize) - ctx.base_log.0;
            mul_const(pt.as_mut_tensor(), 1 << shift);
            println!("second row noise: {:?}", compute_noise(&sk, &row_ct, &pt));
        }
        {
            // check the last row of the RGSW ciphertext
            let row_ct = gsw_ct.get_last_row();
            let mut pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            pt.as_mut_tensor().fill_with_copy(gsw_pt.as_tensor());
            let shift: usize = (Scalar::BITS as usize) - ctx.base_log.0 * ctx.level_count.0;
            mul_const(pt.as_mut_tensor(), 1 << shift);
            println!("last row noise: {:?}", compute_noise(&sk, &row_ct, &pt));
        }

        let mut prod_ct = RLWECiphertext::allocate(ctx.poly_size);
        gsw_ct.external_product(&mut prod_ct, &lwe_ct);
        let mut actual_pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        sk.decrypt_decode_rlwe(&mut actual_pt, &prod_ct, &ctx);

        assert_eq!(actual_pt, gsw_pt);
        println!(
            "final noise: {:?}",
            compute_noise_encoded(&sk, &prod_ct, &gsw_pt, &ctx.codec)
        );
    }

    #[test]
    fn test_negs() {
        let mut ctx = Context::new(TFHEParameters::default());

        // we use another noise
        // so that the initial rlwe ciphertext has noise of ~28 bits,
        // which is the final noise of running trace
        let mut ctx_noisy = Context {
            std: LogStandardDev(-37.5),
            ..Context::new(TFHEParameters::default())
        };

        let sk = ctx.gen_rlwe_sk();
        let neg_sk = {
            let mut pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            for (x, y) in pt.as_mut_tensor().iter_mut().zip(sk.0.as_tensor().iter()) {
                *x = y * Scalar::MAX;
            }
            pt
        };
        let neg_gsw_sk = sk.neg_gsw(&mut ctx);
        // check noise of some rows
        {
            let row_ct = neg_gsw_sk.get_last_row();
            let mut row_pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            row_pt.as_mut_tensor().fill_with_copy(neg_sk.as_tensor());
            let shift: usize =
                (Scalar::BITS as usize) - ctx.negs_base_log.0 * ctx.negs_level_count.0;
            mul_const(row_pt.as_mut_tensor(), 1 << shift);
            println!("last row noise: {:?}", compute_noise(&sk, &row_ct, &row_pt));
        }
        {
            let row_ct = neg_gsw_sk.get_nth_row(1);
            let mut row_pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            row_pt.as_mut_tensor().fill_with_copy(neg_sk.as_tensor());
            let shift: usize = (Scalar::BITS as usize) - ctx.negs_base_log.0;
            mul_const(row_pt.as_mut_tensor(), 1 << shift);
            println!(
                "second row noise: {:?}",
                compute_noise(&sk, &row_ct, &row_pt)
            );
        }

        let one_pt = ctx.gen_unit_pt();
        let mut ct_lwe = RLWECiphertext::allocate(ctx.poly_size);
        sk.ternary_encrypt_rlwe(&mut ct_lwe, &one_pt, &mut ctx_noisy);
        println!(
            "initial noise: {:?}",
            compute_noise_ternary(&sk, &ct_lwe, &one_pt)
        );

        let mut ct_prod = RLWECiphertext::allocate(ctx.poly_size);
        neg_gsw_sk.external_product(&mut ct_prod, &ct_lwe);

        let mut actual = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        sk.ternary_decrypt_rlwe(&mut actual, &ct_prod);

        assert_eq!(actual, neg_sk);
        println!(
            "final noise: {:?}",
            compute_noise_ternary(&sk, &ct_prod, &neg_sk)
        );
    }

    #[test]
    fn test_expand() {
        let mut ctx = Context::new(TFHEParameters::default());

        let sk = ctx.gen_rlwe_sk();
        let neg_sk_ct = sk.neg_gsw(&mut ctx);
        let ksk_map = gen_all_subs_ksk(&sk, &mut ctx);

        let test_pt = ctx.gen_binary_pt();
        let mut test_ct = RLWECiphertext::allocate(ctx.poly_size);
        sk.encode_encrypt_rlwe(&mut test_ct, &test_pt, &mut ctx);

        {
            let zero_cts = make_decomposed_rlwe_ct(&sk, Scalar::one(), &mut ctx);
            let gsw_ct = expand(&zero_cts, &ksk_map, &neg_sk_ct, &ctx); // this should be 1

            // check noise of some rows
            {
                let neg_sk = {
                    let mut pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
                    for (x, y) in pt.as_mut_tensor().iter_mut().zip(sk.0.as_tensor().iter()) {
                        *x = y * Scalar::MAX;
                    }
                    pt
                };
                let row_ct = gsw_ct.get_nth_row(0);
                let mut row_pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
                row_pt
                    .as_mut_tensor()
                    .fill_with_copy(ctx.gen_unit_pt().as_tensor());
                let shift: usize = (Scalar::BITS as usize) - ctx.negs_base_log.0;
                mul_const(row_pt.as_mut_tensor(), 1 << shift);
                naive_update_with_mul(&mut row_pt.as_mut_polynomial(), &neg_sk.as_polynomial());
                println!(
                    "first row noise: {:?}",
                    compute_noise(&sk, &row_ct, &row_pt)
                );
            }
            {
                let row_ct = gsw_ct.get_nth_row(1);
                let mut row_pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
                row_pt
                    .as_mut_tensor()
                    .fill_with_copy(ctx.gen_unit_pt().as_tensor());
                let shift: usize = (Scalar::BITS as usize) - ctx.negs_base_log.0;
                mul_const(row_pt.as_mut_tensor(), 1 << shift);
                println!(
                    "second row noise: {:?}",
                    compute_noise(&sk, &row_ct, &row_pt)
                );
            }
            {
                let row_ct = gsw_ct.get_last_row();
                let mut row_pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
                row_pt
                    .as_mut_tensor()
                    .fill_with_copy(ctx.gen_unit_pt().as_tensor());
                let shift: usize =
                    (Scalar::BITS as usize) - ctx.negs_base_log.0 * ctx.negs_level_count.0;
                mul_const(row_pt.as_mut_tensor(), 1 << shift);
                println!("last row noise: {:?}", compute_noise(&sk, &row_ct, &row_pt));
            }

            println!(
                "average row nosie: {:?}",
                compute_noise_rgsw1(&sk, &gsw_ct, &ctx)
            );

            // decrypt and compare
            let mut lwe_ct = RLWECiphertext::allocate(ctx.poly_size);
            gsw_ct.external_product(&mut lwe_ct, &test_ct);
            let mut pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            sk.decrypt_decode_rlwe(&mut pt, &lwe_ct, &ctx);
            assert_eq!(test_pt, pt);
            println!(
                "final noise: {:?}",
                compute_noise_encoded(&sk, &lwe_ct, &test_pt, &ctx.codec)
            );
        }
        {
            let zero_cts = make_decomposed_rlwe_ct(&sk, Scalar::zero(), &mut ctx);
            let gsw_ct = expand(&zero_cts, &ksk_map, &neg_sk_ct, &ctx);

            // decrypt and compare
            let mut lwe_ct = RLWECiphertext::allocate(ctx.poly_size);
            gsw_ct.external_product(&mut lwe_ct, &test_ct);
            let mut pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            sk.decrypt_decode_rlwe(&mut pt, &lwe_ct, &ctx);
            let zero_pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            assert_eq!(zero_pt, pt);
            println!(
                "final noise: {:?}",
                compute_noise_encoded(&sk, &lwe_ct, &zero_pt, &ctx.codec)
            );
        }
    }

    #[test]
    fn test_fourier_mul() {
        let mut ctx = Context::new(TFHEParameters::default());
        let n = ctx.poly_size;
        let mut out_fourier = Polynomial::allocate(Scalar::zero(), n);
        let mut out_naive = Polynomial::allocate(Scalar::zero(), n);

        let reps = 10;
        for _ in 0..reps {
            let mut a = Polynomial::allocate(Scalar::zero(), n);
            let mut b = Polynomial::allocate(Scalar::zero(), n);
            ctx.random_generator
                .fill_tensor_with_random_uniform_ternary(&mut a);
            ctx.random_generator.fill_tensor_with_random_uniform(&mut b);

            fourier_update_with_mul_acc(&mut out_fourier.as_mut_view(), &a.as_view(), &b.as_view());
            naive_update_with_mul_acc(&mut out_naive, &a, &b);

            for (actual, expected) in out_fourier
                .coefficient_iter()
                .zip(out_naive.coefficient_iter())
            {
                assert!((*actual as f64 - *expected as f64).abs() < 1e-9 * Scalar::MAX as f64);
            }
        }
    }

    #[test]
    fn test_less_eq() {
        let mut ctx = Context::new(TFHEParameters::default());
        let sk = ctx.gen_rlwe_sk();

        let m = ctx.poly_size.0 / 2;
        let mut ptxt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        *ptxt
            .as_mut_polynomial()
            .get_mut_monomial(MonomialDegree(m))
            .get_mut_coefficient() = Scalar::one();

        for i in 1..(ctx.poly_size.0 - m) {
            let mut ct = RLWECiphertext::allocate(ctx.poly_size);
            sk.encode_encrypt_rlwe(&mut ct, &ptxt, &mut ctx);

            ct.less_eq_than(m + i);
            let mut out = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            sk.decrypt_decode_rlwe(&mut out, &ct, &ctx);
            assert_eq!(
                *out.as_polynomial()
                    .get_monomial(MonomialDegree(0))
                    .get_coefficient(),
                Scalar::one()
            );
        }

        for i in 1..(ctx.poly_size.0 - m) {
            let mut ct = RLWECiphertext::allocate(ctx.poly_size);
            sk.encode_encrypt_rlwe(&mut ct, &ptxt, &mut ctx);

            ct.less_eq_than(m - i);
            let mut out = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            sk.decrypt_decode_rlwe(&mut out, &ct, &ctx);
            assert_eq!(
                *out.as_polynomial()
                    .get_monomial(MonomialDegree(0))
                    .get_coefficient(),
                Scalar::zero()
            );
        }
    }

    #[test]
    fn test_eq_to() {
        let mut ctx = Context::new(TFHEParameters::default());
        let sk = ctx.gen_rlwe_sk();

        let m = ctx.poly_size.0 / 2;
        let mut ptxt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        *ptxt
            .as_mut_polynomial()
            .get_mut_monomial(MonomialDegree(m))
            .get_mut_coefficient() = Scalar::one();

        for i in 0..ctx.poly_size.0 {
            let mut ct = RLWECiphertext::allocate(ctx.poly_size);
            sk.encode_encrypt_rlwe(&mut ct, &ptxt, &mut ctx);

            ct.eq_to(i);
            let mut out = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            sk.decrypt_decode_rlwe(&mut out, &ct, &ctx);
            let res = *out
                .as_polynomial()
                .get_monomial(MonomialDegree(0))
                .get_coefficient();
            if i == m {
                assert_eq!(res, 1);
            } else {
                assert_eq!(res, 0);
            }
        }
    }

    #[test]
    fn test_compute_noise() {
        let mut ctx = Context::new(TFHEParameters::default());
        let sk = ctx.gen_rlwe_sk();

        let zero_msg = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        let mut binary_msg = ctx.gen_binary_pt();
        ctx.codec.poly_encode(&mut binary_msg.as_mut_polynomial());

        let mut ct = RLWECiphertext::allocate(ctx.poly_size);
        let mut ct_zero = RLWECiphertext::allocate(ctx.poly_size);
        sk.encrypt_rlwe(&mut ct, &binary_msg, ctx.std, &mut ctx.encryption_generator);
        sk.encrypt_rlwe(
            &mut ct_zero,
            &zero_msg,
            ctx.std,
            &mut ctx.encryption_generator,
        );

        // the real support in all of the reals, but we need to approximate it
        // the log support is about log2(6*sigma), and sigma = Scalar::MAX * error_std
        let max_log_support = 3 + i64::from(Scalar::BITS) + ctx.std.get_log_standard_dev() as i64;
        println!("support: {max_log_support:?}");

        let noise_0 = compute_noise(&sk, &ct, &binary_msg);
        println!("noise_0: {noise_0:?}");
        assert!(noise_0 < max_log_support as f64);

        // now if we add another ciphertext then the noise should increase
        ct.update_with_add(&ct_zero);
        let noise_1 = compute_noise(&sk, &ct, &binary_msg);
        println!("noise_1: {noise_1:?}");
        assert!(noise_0 < noise_1);
        // assert!(noise_1 < max_log_support as f64);
    }

    #[test]
    fn test_not_in_place() {
        let mut ctx = Context {
            codec: Codec::new(2),
            ..Context::new(TFHEParameters::default())
        };
        let sk = ctx.gen_rlwe_sk();

        let one = ctx.gen_unit_pt();
        let mut one_ct = RLWECiphertext::allocate(ctx.poly_size);
        sk.encode_encrypt_rlwe(&mut one_ct, &one, &mut ctx);
        one_ct.not_in_place();
        let mut actual = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        sk.decrypt_decode_rlwe(&mut actual, &one_ct, &ctx);
        let expected = ctx.gen_zero_pt();
        assert_eq!(expected, actual);

        {
            one_ct.not_in_place();
            let mut actual = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            sk.decrypt_decode_rlwe(&mut actual, &one_ct, &ctx);
            let expected = ctx.gen_unit_pt();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_not() {
        let mut ctx = Context {
            codec: Codec::new(2),
            ..Context::new(TFHEParameters::default())
        };
        let sk = ctx.gen_rlwe_sk();

        let one = ctx.gen_unit_pt();
        let mut one_ct = RLWECiphertext::allocate(ctx.poly_size);
        sk.encode_encrypt_rlwe(&mut one_ct, &one, &mut ctx);

        {
            let mut actual = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            sk.decrypt_decode_rlwe(&mut actual, &one_ct.not(), &ctx);
            assert_eq!(ctx.gen_zero_pt(), actual);
        }

        {
            let mut actual = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
            sk.decrypt_decode_rlwe(&mut actual, &one_ct.not().not(), &ctx);
            assert_eq!(ctx.gen_unit_pt(), actual);
        }
    }

    #[test]
    fn test_expand_slow() {
        let mut ctx = Context {
            poly_size: PolynomialSize(256),
            ks_level_count: DecompositionLevelCount(11),
            ..Context::new(TFHEParameters::default())
        };
        // let mut ctx = Context::new(TFHEParameters::default());

        // setup keys
        let lwe_sk = ctx.gen_lwe_sk();
        let rlwe_sk = lwe_sk.to_rlwe_sk();
        let neg_sk_ct = rlwe_sk.neg_gsw(&mut ctx);
        let mut ksks = LWEtoRLWEKeyswitchKey::allocate(&ctx);
        ksks.fill_with_keyswitching_key(&lwe_sk, &mut ctx);

        // create a test plaintext and encrypt it
        // which we will multiply with an rgsw ciphertext encryption of 1 later
        // to check the correctness of the rgsw ciphertext
        let test_pt = ctx.gen_unit_pt();
        let mut test_ct = RLWECiphertext::allocate(ctx.poly_size);
        rlwe_sk.encode_encrypt_rlwe(&mut test_ct, &test_pt, &mut ctx);

        // create the decomposed ciphertexts and then do the conversion
        let cts = make_decomposed_rlwe_ct2(&rlwe_sk, Scalar::one(), &mut ctx);
        let actual_rgsw = expand_slow(&cts, &ksks, &neg_sk_ct, &ctx);

        // check correctness
        let mut actual_rlwe = RLWECiphertext::allocate(ctx.poly_size);
        actual_rgsw.external_product(&mut actual_rlwe, &test_ct);
        let mut pt = PlaintextList::allocate(Scalar::zero(), ctx.plaintext_count());
        rlwe_sk.decrypt_decode_rlwe(&mut pt, &actual_rlwe, &ctx);
        assert_eq!(test_pt, pt);

        println!(
            "average row noise: {:?}",
            compute_noise_rgsw1(&rlwe_sk, &actual_rgsw, &ctx)
        );

        println!(
            "final noise: {:?}",
            compute_noise_encoded(&rlwe_sk, &actual_rlwe, &pt, &ctx.codec)
        );
    }
}
