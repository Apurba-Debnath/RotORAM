#![allow(unused)]
/*
use concrete_core::commons::math::tensor::{AsRefSlice, Tensor};
use concrete_core::{
    commons::{
        crypto::{
            encoding::Plaintext,
            lwe::{LweBody, LweCiphertext, LweMask},
            secret::generators::SecretRandomGenerator,
            secret::{generators::EncryptionRandomGenerator, LweSecretKey},
        },
        math::{
            decomposition::SignedDecomposer,
            polynomial::Polynomial,
            tensor::{AsMutTensor, AsRefTensor},
        },
    },
    prelude::{
        BinaryKeyKind, DispersionParameter, LweDimension, LweSize, MonomialDegree, PolynomialSize,
    },
};
use concrete_csprng::generators::SoftwareRandomGenerator;
*/

use tfhe::{
    core_crypto::entities::plaintext::Plaintext,

    core_crypto::entities::lwe_ciphertext::{LweBody, LweCiphertext, LweMask},

    core_crypto::commons::generators::{SecretRandomGenerator, EncryptionRandomGenerator},
    core_crypto::entities::lwe_secret_key::LweSecretKey,

    core_crypto::commons::math::decomposition::SignedDecomposer,
    core_crypto::entities::polynomial::Polynomial,
    
    core_crypto::commons::dispersion::DispersionParameter,
    core_crypto::commons::parameters::{
        LweDimension,
        LweSize,
        MonomialDegree,
        PolynomialSize
    },

    core_crypto::prelude::CiphertextModulus,
    core_crypto::prelude::{LweBodyRef, LweBodyRefMut},
    core_crypto::commons::math::random::Distribution,
    core_crypto::algorithms::lwe_encryption::encrypt_lwe_ciphertext,
    core_crypto::commons::math::random::UniformBinary,

    core_crypto::prelude::decrypt_lwe_ciphertext,

    core_crypto::algorithms::glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext,
};

use tfhe_csprng::generators::SoftwareRandomGenerator;

use crate::{
    context::Context,
    num_types::{Scalar, Zero},
    rgsw::RGSWCiphertext,
    rlwe::{RLWECiphertext, RLWESecretKey},
    utils::mul_const,
};

#[derive(Debug, Clone)]
/// An LWE ciphertext.
pub struct LWECiphertext(pub(crate) LweCiphertext<Vec<Scalar>>);

impl LWECiphertext {
    /*
    #[deprecated = "use `new`"]
    pub fn allocate(size: LweSize) -> Self {
        Self(LweCiphertext::new(Scalar::zero(), size, 
                CiphertextModulus::new_native()))
    }
    */

    // NOTE(abheet): replace `allocate` with this `new` function, it takes a
    // custom modulus as another argument.
    pub fn new(size: LweSize, ciphertext_modulus: CiphertextModulus<Scalar>) -> Self {
        Self(LweCiphertext::new(Scalar::zero(), size, ciphertext_modulus))
    }

    /// Return the length of the mask + 1 for the body.
    pub fn lwe_size(&self) -> LweSize {
        self.0.lwe_size()
    }

    // NOTE(abheet): modified!
    pub fn get_body(&self) -> LweBodyRef<'_, Scalar> {
        self.0.get_body()
    }

    pub fn get_mask(&self) -> LweMask<&[Scalar]> {
        self.0.get_mask()
    }

    pub fn get_mut_mask(&mut self) -> LweMask<&mut [Scalar]> {
        self.0.get_mut_mask()
    }

    // NOTE(abheet): modified!
    pub fn get_mut_body(&mut self) -> LweBodyRefMut<'_, Scalar> {
        self.0.get_mut_body()
    }

    // NOTE(abheet): modified!
    pub fn clear(&mut self) {
        // self.0.as_mut_tensor().fill_with(Scalar::zero);
        self.0.as_mut().fill_with(Scalar::zero);
    }

    // NOTE(abheet): modified!
    pub fn fill_with_sample_extract(&mut self, c: &RLWECiphertext, n_th: MonomialDegree) {
        // self.0.fill_with_glwe_sample_extraction(&c.0, n_th);
        extract_lwe_sample_from_glwe_ciphertext(
            &c.0,
            &mut self.0,
            n_th,
        );
    }

    // NOTE(abheet): modified!
    pub fn fill_with_const_sample_extract(&mut self, c: &RLWECiphertext) {
        // self.0
        //     .fill_with_glwe_sample_extraction(&c.0, MonomialDegree(0));

        extract_lwe_sample_from_glwe_ciphertext(
            &c.0,
            &mut self.0,
            MonomialDegree(0),
        );
    }

    /*
    // NOTE(abheet): no tensors are to be used, there are other ways to
    // implement these functions if needed.
    //
    pub fn fill_with_tensor<C>(&mut self, t: &Tensor<C>)
    where
        Tensor<C>: AsRefSlice<Element = Scalar>,
    {
        self.0.as_mut_tensor().fill_with_copy(t);
    }

    pub fn as_tensor(&self) -> &Tensor<Vec<Scalar>> {
        self.0.as_tensor()
    }
    */
}

#[derive(Debug, Clone)]
/// An LWE secret key.
// NOTE(abheet): The BinaryKeyKind is one of the kinds that could be specified
// by the user in a generic case. In this case we are hardcoding the rest of the
// functions to work with binary key kind only.
pub struct LWESecretKey(pub(crate) LweSecretKey</* BinaryKeyKind, */ Vec<Scalar>>);

impl LWESecretKey {
    // TODO(abheet): this function has been replaced with generate_new_binary.
    //
    // /// Generate a secret key where the coefficients are binary.
    // pub fn generate_binary(
    //     lwe_dimension: LweDimension,
    //     generator: &mut SecretRandomGenerator<SoftwareRandomGenerator>,
    // ) -> Self {
    //     Self(LweSecretKey::generate_binary(lwe_dimension, generator))
    // }

    /// Generate a secret key where the coefficients are binary.
    pub fn generate_new_binary(
        lwe_dimension: LweDimension,
        generator: &mut SecretRandomGenerator<SoftwareRandomGenerator>,
    ) -> Self {
        Self(LweSecretKey::generate_new_binary(lwe_dimension, generator))
    }

    // NOTE(abheet): replaced with `encrypt_lwe_binary`,
    //
    // pub fn encrypt_lwe(
    //     &self,
    //     output: &mut LWECiphertext,
    //     pt: &Plaintext<Scalar>,
    //     noise_parameters: impl DispersionParameter,
    //     generator: &mut EncryptionRandomGenerator<SoftwareRandomGenerator>,
    // ) {
    //     self.0
    //         .encrypt_lwe(&mut output.0, pt, noise_parameters, generator);
    // }

    /// Could be used only with 
    pub fn encrypt_lwe_binary(
        &self,
        output: &mut LWECiphertext,
        pt: &Plaintext<Scalar>,
        // noise_parameters: impl DispersionParameter,
        noise_distribution: UniformBinary, // TODO(abheet): is this sound?
        generator: &mut EncryptionRandomGenerator<SoftwareRandomGenerator>,
    ) {
        /*
        self.0
            .encrypt_lwe(&mut output.0, pt, noise_parameters, generator);
        */
        encrypt_lwe_ciphertext(&self.0, &mut output.0, *pt, noise_distribution, generator);
    }

    // NOTE(abheet): modified!
    pub fn encode_encrypt_lwe(
        &self,
        output: &mut LWECiphertext,
        pt: &Plaintext<Scalar>,
        ctx: &mut Context,
    ) {
        let mut encoded_pt = *pt;
        ctx.codec.encode(&mut encoded_pt.0);
        // self.encrypt_lwe(output, &encoded_pt, ctx.std, &mut ctx.encryption_generator);

        // TODO(abheet): is this correct?
        self.encrypt_lwe_binary(output, &encoded_pt, UniformBinary, &mut ctx.encryption_generator);
    }

    // NOTE(abheet): modified!
    pub fn decrypt_lwe(&self, output: &mut Plaintext<Scalar>, ct: &LWECiphertext) {
        // self.0.decrypt_lwe(output, &ct.0);
        *output = decrypt_lwe_ciphertext(
            &self.0, &ct.0);
    }

    /// Decrypt a LWE ciphertext and then decode.
    pub fn decode_decrypt_lwe(
        &self,
        pt: &mut Plaintext<Scalar>,
        encrypted: &LWECiphertext,
        ctx: &Context,
    ) {
        self.decrypt_lwe(pt, encrypted);
        ctx.codec.decode(&mut pt.0);
    }

    // NOTE(abheet): modified!
    pub fn to_rlwe_sk(&self) -> RLWESecretKey {
        // TODO(abheet): is this correct?
        let mut sk = RLWESecretKey::zero(PolynomialSize(self.0.as_ref().len()));
        sk.fill_with_slice(self.0.as_ref());
        sk
    }

    // NOTE(abheet): modified!
    pub fn key_size(&self) -> LweDimension {
        // self.0.key_size()
        
        // TODO(abheet): is length of the inner container same as key
        // size?
        LweDimension(self.0.as_ref().len())
    }
}

// NOTE(abheet): Will be done later as needed!
/*
#[derive(Debug, Clone)]
/// An LWE to RLWE key switching key.
pub struct LWEtoRLWEKeyswitchKey {
    // TODO At the moment it's a list of full RGSW ciphertexts,
    // we should remove half of the rows.
    pub(crate) inner: Vec<RGSWCiphertext>,
}

impl LWEtoRLWEKeyswitchKey {
    pub fn allocate(ctx: &Context) -> Self {
        Self {
            inner: vec![
                RGSWCiphertext::allocate(ctx.poly_size, ctx.base_log, ctx.level_count);
                ctx.poly_size.0
            ],
        }
    }

    pub fn fill_with_keyswitching_key(&mut self, sk: &LWESecretKey, ctx: &mut Context) {
        assert_eq!(ctx.poly_size.0, sk.key_size().0);
        let rlwe_sk = sk.to_rlwe_sk();
        self.inner = vec![];
        for s in sk.0.as_tensor().iter() {
            // TODO what is the decomposition parameters?
            let mut rgsw_ct =
                RGSWCiphertext::allocate(ctx.poly_size, ctx.ks_base_log, ctx.ks_level_count);
            rlwe_sk.encrypt_constant_rgsw(&mut rgsw_ct, &Plaintext(*s), ctx);
            self.inner.push(rgsw_ct);
        }
    }
}
*/
#[derive(Debug, Clone)]
/// An LWE to RLWE key switching key.
/// One RGSW ciphertext per LWE-key coefficient `s_i`, each an RGSW
/// encryption of the *constant* `s_i` under the derived RLWE key.
pub struct LWEtoRLWEKeyswitchKey {
    pub(crate) inner: Vec<RGSWCiphertext>,
}

impl LWEtoRLWEKeyswitchKey {
    pub fn allocate(ctx: &Context) -> Self {
        Self {
            inner: vec![
                // NOTE: ks_* params here, to match fill_with_keyswitching_key
                // and the decomposer used in conv_lwe_to_rlwe.
                RGSWCiphertext::allocate(
                    ctx.poly_size,
                    ctx.ks_base_log,
                    ctx.ks_level_count,
                    ctx.modulus,          // <- new modulus arg
                );
                ctx.poly_size.0
            ],
        }
    }

    pub fn fill_with_keyswitching_key(&mut self, sk: &LWESecretKey, ctx: &mut Context) {
        assert_eq!(ctx.poly_size.0, sk.key_size().0);
        let rlwe_sk = sk.to_rlwe_sk();
        self.inner = Vec::with_capacity(ctx.poly_size.0);
        // was: for s in sk.0.as_tensor().iter()  -> Tensor API removed
        for &s in sk.0.as_ref().iter() {
            let mut rgsw_ct = RGSWCiphertext::allocate(
                ctx.poly_size,
                ctx.ks_base_log,
                ctx.ks_level_count,
                ctx.modulus,
            );
            rlwe_sk.encrypt_constant_rgsw(&mut rgsw_ct, &Plaintext(s), ctx);
            self.inner.push(rgsw_ct);
        }
    }
}

/*
pub fn conv_lwe_to_rlwe(
    ksks: &LWEtoRLWEKeyswitchKey,
    lwe: &LWECiphertext,
    ctx: &Context,
) -> RLWECiphertext {
    let mut out = RLWECiphertext::allocate(ctx.poly_size);

    for (ksk, a) in ksks.inner.iter().zip(lwe.get_mask().as_tensor().iter()) {
        // Setup decomposition stuff
        // TODO what parameters for decomposition?
        let decomposer = SignedDecomposer::new(ctx.ks_base_log, ctx.ks_level_count);
        let closest = decomposer.closest_representable(*a);
        let decomposer_iter = decomposer.decompose(closest);

        // Get an iterator of every second row
        // we only need every second ciphertext since that is
        // a valid RLWE ciphertext in a RGSW
        let ksk_iter = ksk.0.level_matrix_iter().rev().map(|m| {
            let ct = m.row_iter().nth(1).unwrap().into_glwe();
            // TODO avoid copying
            let mut out = RLWECiphertext::allocate(ctx.poly_size);
            out.update_mask_with_add(&ct.get_mask().as_polynomial_list().get_polynomial(0));
            out.update_body_with_add(&ct.get_body().as_polynomial());
            out
        });

        for (mut ct, decomposed_a) in ksk_iter.zip(decomposer_iter) {
            mul_const(
                ct.get_mut_mask()
                    .as_mut_polynomial_list()
                    .get_mut_polynomial(0)
                    .as_mut_tensor(),
                decomposed_a.value(),
            );
            mul_const(
                ct.get_mut_body().as_mut_polynomial().as_mut_tensor(),
                decomposed_a.value(),
            );
            out.get_mut_mask()
                .as_mut_polynomial_list()
                .get_mut_polynomial(0)
                .update_with_wrapping_sub(&ct.get_mask().as_polynomial_list().get_polynomial(0));
            out.get_mut_body()
                .as_mut_polynomial()
                .update_with_wrapping_sub(&ct.get_body().as_polynomial());
        }
    }

    let b_poly = {
        let mut v = vec![Scalar::zero(); ctx.poly_size.0];
        v[0] = lwe.get_body().0;
        Polynomial::from_container(v)
    };

    out.get_mut_body()
        .as_mut_polynomial()
        .update_with_wrapping_add(&b_poly);
    out
}
*/
pub fn conv_lwe_to_rlwe(
    ksks: &LWEtoRLWEKeyswitchKey,
    lwe: &LWECiphertext,
    ctx: &Context,
) -> RLWECiphertext {
    let n = ctx.poly_size.0;
    let mut out = RLWECiphertext::allocate(ctx.poly_size, ctx.modulus);

    // LWE ciphertext is laid out as [a_0, ..., a_{n-1}, b].
    let lwe_data = lwe.0.as_ref();
    let mask = &lwe_data[..n];
    let body = lwe_data[n];

    let decomposer =
        SignedDecomposer::<Scalar>::new(ctx.ks_base_log, ctx.ks_level_count);

    // out = - sum_i a_i * RLWE(s_i)
    for (ksk, &a) in ksks.inner.iter().zip(mask.iter()) {
        let closest = decomposer.closest_representable(a);
        for term in decomposer.decompose(closest) {
            // decomposition level `ell` (1-indexed) has gadget 2^{BITS - base_log*ell};
            // the matching RGSW message-row is flat index (2*ell - 1).
            let ell = term.level().0;
            let mut row = ksk.get_nth_row(2 * ell - 1); // RLWE(s_i * gadget_ell)
            // scale the whole RLWE (mask AND body) by the signed digit
            mul_const(row.0.as_mut(), term.value());
            // accumulate: out -= a_i^{(ell)} * RLWE(s_i * gadget_ell)
            out.update_with_sub(&row);
        }
    }

    // add b to the constant term: out_body[0] += b
    {
        let mut get_mut_out_body = out.get_mut_body();
        let out_body = get_mut_out_body.as_mut();
        out_body[0] = out_body[0].wrapping_add(body);
    }

    out
}

// NOTE(abheet): tests have not been migrated yet, DO NOT RUN the tests.
#[cfg(test)]
mod test {
    use concrete_core::prelude::PolynomialSize;

    use crate::params::TFHEParameters;

    use super::*;

    #[test]
    fn test_lwe() {
        let mut ctx = Context::new(TFHEParameters::default());
        let sk = LWESecretKey::generate_binary(ctx.lwe_dim(), &mut ctx.secret_generator);
        for _ in 0..10 {
            let expected = ctx.gen_scalar_binary_pt();
            let mut ct = LWECiphertext::allocate(ctx.lwe_size());
            sk.encode_encrypt_lwe(&mut ct, &expected, &mut ctx);

            let mut actual = ctx.gen_scalar_zero_pt();
            sk.decode_decrypt_lwe(&mut actual, &ct, &ctx);
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_lwe_fill() {
        let mut ctx = Context::new(TFHEParameters::default());
        let sk = LWESecretKey::generate_binary(ctx.lwe_dim(), &mut ctx.secret_generator);

        let expected = ctx.gen_scalar_binary_pt();
        let mut ct = LWECiphertext::allocate(ctx.lwe_size());
        sk.encode_encrypt_lwe(&mut ct, &expected, &mut ctx);

        let mut ct2 = LWECiphertext::allocate(ctx.lwe_size());
        ct2.fill_with_tensor(ct.as_tensor());

        let mut actual = ctx.gen_scalar_zero_pt();
        sk.decode_decrypt_lwe(&mut actual, &ct2, &ctx);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_lwe_to_rlwe() {
        let mut ctx = Context {
            poly_size: PolynomialSize(1024),
            ..Context::new(TFHEParameters::default())
        };

        let lwe_sk = LWESecretKey::generate_binary(ctx.lwe_dim(), &mut ctx.secret_generator);
        let rlwe_sk = lwe_sk.to_rlwe_sk();
        let expected = ctx.gen_scalar_binary_pt();

        // create ciphertext
        let mut lwe_ct = LWECiphertext::allocate(ctx.lwe_size());
        lwe_sk.encode_encrypt_lwe(&mut lwe_ct, &expected, &mut ctx);

        // create ksk
        let mut ksks = LWEtoRLWEKeyswitchKey::allocate(&ctx);
        ksks.fill_with_keyswitching_key(&lwe_sk, &mut ctx);

        // switch it to a rlwe ciphertext and decrypt
        let rlwe_ct = conv_lwe_to_rlwe(&ksks, &lwe_ct, &ctx);
        let mut actual = ctx.gen_zero_pt();
        rlwe_sk.decrypt_decode_rlwe(&mut actual, &rlwe_ct, &ctx);

        // find the constant term and compare
        assert_eq!(*actual.plaintext_iter().next().unwrap(), expected);
    }

    #[test]
    fn test_sample_extract() {
        let mut ctx = Context::new(TFHEParameters::default());
        let lwe_sk = LWESecretKey::generate_binary(ctx.lwe_dim(), &mut ctx.secret_generator);
        let rlwe_sk = lwe_sk.to_rlwe_sk();

        // create a ciphertext
        let pt = ctx.gen_binary_pt();
        let mut rlwe_ct = RLWECiphertext::allocate(ctx.poly_size);
        rlwe_sk.encode_encrypt_rlwe(&mut rlwe_ct, &pt, &mut ctx);

        // make sample extract
        let mut lwe_ct = LWECiphertext::allocate(ctx.lwe_size());
        lwe_ct.fill_with_const_sample_extract(&rlwe_ct);

        // decrypt and compare
        let mut actual_pt = Plaintext(Scalar::zero());
        lwe_sk.decode_decrypt_lwe(&mut actual_pt, &lwe_ct, &ctx);
        assert_eq!(*pt.as_tensor().get_element(0), actual_pt.0);
    }
}
