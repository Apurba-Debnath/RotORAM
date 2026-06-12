#![allow(unused)]

use crate::{
    context::{Context, FftBuffer},
    decision_tree::{bit_decomposed_rgsw, demux_with},
    naive_hash::NaiveHash,
    num_types::{One, Scalar, Zero},
    params::{TFHEParameters, MASK_SEED},
    lwe::{LWEtoRLWEKeyswitchKey, LWECiphertext, LWESecretKey, conv_lwe_to_rlwe},
    rgsw::{RGSWCiphertext, external_product_fourier},
    rlwe::{decomposed_rlwe_to_rgsw, RLWECiphertext, RLWESecretKey, RLWEKeyswitchKey, FourierRLWEKeyswitchKey},
    utils::pt_to_lossy_u64,
    utils::{transpose, log2},
};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

use tfhe::{
    core_crypto::entities::plaintext::Plaintext,
    core_crypto::entities::plaintext_list::PlaintextList,
    core_crypto::commons::parameters::{LweSize, MonomialDegree},
    core_crypto::commons::math::random::UniformBinary
};

use rayon::prelude::*;
use std::{
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
    collections::HashMap,
};

/// Deterministic public mask, identical on client and server.
pub fn gen_fixed_mask(seed: u64, n: usize) -> Vec<Scalar> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n).map(|_| rng.gen::<Scalar>()).collect()
}

/// Exact negacyclic product in Z_q[X]/(X^N+1). O(N^2), used once per query.
pub fn negacyclic_mul(a: &[Scalar], b: &[Scalar], n: usize) -> Vec<Scalar> {
    let mut out = vec![Scalar::zero(); n];
    for i in 0..n {
        if a[i] == 0 { continue; }
        for j in 0..n {
            let k = i + j;
            let prod = a[i].wrapping_mul(b[j]);
            if k < n { out[k] = out[k].wrapping_add(prod); }
            else     { out[k - n] = out[k - n].wrapping_sub(prod); } // X^N = -1
        }
    }
    out
}

// ORAM client state.
pub struct Client {
    pub sk: RLWESecretKey,
    pub ctx: Context,
    pub rows: usize,
    pub cols: usize,
}

impl Client {
    /// Setup a new client. Set rows = 1 if no batching is required.
    /// The exact number of elements in the database depends on the
    /// number of hash functions.
    pub fn new(rows: usize, cols: usize, params: TFHEParameters) -> Self {
        let mut ctx = Context::new(params);
        let sk = ctx.gen_rlwe_sk();
        Self {
            sk,
            ctx,
            rows,
            cols,
        }
    }

    // Generate the -s keyswitching key.
    pub fn gen_neg_sk(&mut self) -> RGSWCiphertext {
        self.sk.neg_gsw(&mut self.ctx)
    }

    pub fn encrypt_database_transposed(&mut self, db: &[u64], delta_scaled: Scalar) -> Vec<RLWECiphertext> {
        let n = self.ctx.poly_size.0;
        let m = db.len() / n;                       // number of original rows
        debug_assert!(m <= n, "full-row transpose mode requires item_count <= N^2");
        let mut out = Vec::with_capacity(n);
        for j in 0..n {                             // one transposed poly per column j
            let mut pt = self.ctx.gen_zero_pt();
            for k in 0..m {                         // coeff k = original row k, column j
                pt.as_mut()[k] = delta_scaled.wrapping_mul(db[k * n + j]);
            }
            let mut ct = RLWECiphertext::allocate(self.ctx.poly_size, self.ctx.modulus);
            self.sk.encrypt_rlwe_binary(&mut ct, &pt, UniformBinary, &mut self.ctx.encryption_generator);
            out.push(ct);
        }
        out
    }

    // Generate a dummy database for performance testing.
    // pub fn gen_dummy_database(&mut self) -> (Vec<PlaintextList<Vec<Scalar>>>, Vec<Vec<RLWECiphertext>>) {}
    pub fn gen_dummy_database(&mut self) -> Vec<u64> {
        // TODO put NaiveHash in Client struct
        println!("\nCreating dummy database for performace testing");
        let item_count = self.rows * self.cols;
        println!("\n(line125_oram.rs): Ciphertext modulus:{:?}",self.ctx.modulus);
        // println!("\nTotal data elements in the database is:{:?}",item_count);
        let mut db = vec![item_count];

        let max_db_element:u64=self.ctx.codec.pt_modulus(); // 128;  //150500;
        println!("Plaintext mod:{:?}",max_db_element);

        let mut db: Vec<u64> = Vec::with_capacity(item_count);

        //create encrypted data vector
        // let mut enc_db: Vec<RLWECiphertext> = Vec::with_capacity(item_count);

        let mut i=0;
        while (item_count > i) {
            let data_item=rand::thread_rng().gen_range(0..max_db_element);
            // let data_item = (i as u64) % 32;
            // let data_item = ((i*2+3) as u64) % max_db_element;

            db.push(data_item);
            i+=1;            
        }
        db
    }

    pub fn decrypt_final_result(& mut self, query:RLWECiphertext) -> PlaintextList<Vec<u64>> {

        let mut pt = self.ctx.gen_zero_pt();
        // self.sk.decrypt_rlwe(&mut pt, &query); 
        self.sk.decrypt_decode_rlwe(&mut pt, &query, &mut self.ctx);
        pt
    }

/// One-time key so the server can move an extracted LWE coeff back to RLWE coeff 0.
pub fn gen_lwe_to_rlwe_ksk(&mut self) -> LWEtoRLWEKeyswitchKey {
    // RLWE secret key, viewed as the LWE key that sample-extraction produces.
    let lwe_sk = LWESecretKey(self.sk.0.clone().into_lwe_secret_key());
    let mut ksk = LWEtoRLWEKeyswitchKey::allocate(&self.ctx);
    ksk.fill_with_keyswitching_key(&lwe_sk, &mut self.ctx);
    ksk
}

/// Write query for row r*: (forward rot, reverse rot, sign-folded new row).
pub fn gen_row_write_query(
    &mut self,
    row: usize,
    new_row: &[u64],
    delta_scaled: Scalar,
) -> (RGSWCiphertext, RGSWCiphertext, RLWECiphertext) {
    let n = self.ctx.poly_size.0;
    let s_neg = row != 0;                       // s = -1 iff row != 0

    // forward rotation X^{N - r*}  (same as read)
    let fwd_deg = (n - row) % n;
    let mut fwd_pt = self.ctx.gen_zero_pt();
    fwd_pt.as_mut()[fwd_deg] = 1;
    let mut fwd = RGSWCiphertext::allocate(
        self.ctx.poly_size, self.ctx.base_log, self.ctx.level_count, self.ctx.modulus);
    self.sk.encrypt_rgsw(&mut fwd, &fwd_pt, &mut self.ctx);

    // reverse rotation = inverse monomial of X^{N-r*}: +X^0 if r*=0 else -X^{r*}
    let mut rev_pt = self.ctx.gen_zero_pt();
    if row == 0 { rev_pt.as_mut()[0] = 1; }
    else        { rev_pt.as_mut()[row] = Scalar::MAX; }   // -1 mod q (q = 2^64)
    let mut rev = RGSWCiphertext::allocate(
        self.ctx.poly_size, self.ctx.base_log, self.ctx.level_count, self.ctx.modulus);
    self.sk.encrypt_rgsw(&mut rev, &rev_pt, &mut self.ctx);

    // packed new row at Δ_s, with sign s folded in: coeff j = s · Δ_s · new[j]
    let mut pt = self.ctx.gen_zero_pt();
    for j in 0..n {
        let v = delta_scaled.wrapping_mul(new_row[j]);
        pt.as_mut()[j] = if s_neg { v.wrapping_neg() } else { v };
    }
    let mut ct_new = RLWECiphertext::allocate(self.ctx.poly_size, self.ctx.modulus);
    self.sk.encrypt_rlwe_binary(&mut ct_new, &pt, UniformBinary, &mut self.ctx.encryption_generator);

    (fwd, rev, ct_new)
}

}

// apd - CDKS packing updates
/// Multiply an RLWE ciphertext by (± X^shift) in Z_q[X]/(X^N+1), exactly.
/// This is a negacyclic rotation — no FFT, no rounding.
fn rotate_poly(dst: &mut [Scalar], src: &[Scalar], shift: usize, negate: bool, n: usize) {
    for i in 0..n {
        let j = (i + shift) % n;
        let crossed = ((i + shift) / n) % 2 == 1; // X^N = -1
        let mut v = src[i];
        if crossed ^ negate {
            v = v.wrapping_neg();
        }
        dst[j] = v;
    }
}

fn monomial_mul(ct: &RLWECiphertext, shift: usize, negate: bool, ctx: &Context) -> RLWECiphertext {
    let n = ctx.poly_size.0;
    let mut out = RLWECiphertext::allocate(ctx.poly_size, ctx.modulus);
    rotate_poly(out.get_mut_mask().as_mut(), ct.get_mask().as_ref(), shift, negate, n);
    rotate_poly(out.get_mut_body().as_mut(), ct.get_body().as_ref(), shift, negate, n);
    out
}

/// Recursive CDKS PackLWEs.
/// Packs rlwe_cts[start_idx .. ] so that the constant coefficient of input k
/// lands in coefficient k of the output, scaled by N. Non-constant input
/// coefficients are annihilated. 
fn pack_lwes_cdks(
    ctx: &Context,
    ell: usize,
    start_idx: usize,
    rlwe_cts: &[RLWECiphertext],
    subs_ksk_map: &HashMap<usize, RLWEKeyswitchKey>,
) -> RLWECiphertext {
    if ell == 0 {
        return rlwe_cts[start_idx].clone();
    }
    let n = ctx.poly_size.0;
    let log_n = log2(n);
    let step = 1 << (log_n - ell);

    let mut ct_even = pack_lwes_cdks(ctx, ell - 1, start_idx, rlwe_cts, subs_ksk_map);
    let ct_odd = pack_lwes_cdks(ctx, ell - 1, start_idx + step, rlwe_cts, subs_ksk_map);

    // y = X^step, neg_y = -X^step
    let y_times_ct_odd = monomial_mul(&ct_odd, step, false, ctx);
    let neg_y_times_ct_odd = monomial_mul(&ct_odd, step, true,  ctx);

    let mut ct_sum_1 = ct_even.clone();
    ct_sum_1.update_with_add(&neg_y_times_ct_odd);  // ct_even - X^step·ct_odd
    ct_even.update_with_add(&y_times_ct_odd);   // ct_even + X^step·ct_odd

    let k = (1 << ell) + 1;
    let ksk = subs_ksk_map.get(&k).expect("missing subs_ksk");
    let mut ct_auto = RLWECiphertext::allocate(ctx.poly_size, ctx.modulus);
    ksk.subs(&mut ct_auto, &ct_sum_1);

    ct_even.update_with_add(&ct_auto);
    ct_even
}

pub struct PackOfflineData {
    o: RLWECiphertext, // O = Pack(masks, 0), reusable across queries
}

pub struct Server {
    data_enc: Vec<RLWECiphertext>,
    neg_s: RGSWCiphertext,
    ctx: Context,
}

impl Server {
    /// Create a new server that stores ciphertexts `data`.
    pub fn new(
        data_enc: Vec<RLWECiphertext>,
        neg_s: RGSWCiphertext,
        params: TFHEParameters,
    ) -> Self {
        Self {
            data_enc,
                // .into_iter()
                // .map(|row| Arc::new(RwLock::new(row)))
                // .collect(),
            neg_s,
            ctx: Context::new(params),
        }
    }

    fn rows(&self) -> usize {
        self.data_enc.len()
    }

    fn cols(&self) -> usize {
        // self.data[0].clone().read().unwrap().len()
        self.data_enc.clone().len()
    }

    // applying rotation on the packed ciphertext with RGSW ciphertext as rotation polynomial
    pub fn rlwe_ct_rotation(
        &self,
        packed_ct: &RLWECiphertext,
        idx_rgsw_ct: &RGSWCiphertext,    // RGSW encryption of X^(N - msb_index)
    ) -> RLWECiphertext {
        let mut buf = self.ctx.gen_fft_ctx();
        let mut result = RLWECiphertext::allocate(self.ctx.poly_size, self.ctx.modulus);
    
        idx_rgsw_ct.external_product_with_buf(
            &mut result,
            packed_ct,
            &mut buf,
        );
    
        result
    }

    // apd - CDKS packing updates
    pub fn pack_first_coeffs_cdks(
        &self,
        input_rlwe_cts: &[RLWECiphertext],
        subs_ksk_map: &HashMap<usize, RLWEKeyswitchKey>,
    ) -> RLWECiphertext {
        let n = self.ctx.poly_size.0;
        // let log_n = log2(n);
        let g = input_rlwe_cts.len();
        debug_assert!(g >= 1 && g.is_power_of_two(), "g must be a power of two");

        // Stride: place input k at array position k * s, zeros elsewhere.
        let s = n / g;
        let log_g = log2(g);
        
        // Pad to exactly N inputs with zero ciphertexts.
        // let mut cts: Vec<RLWECiphertext> = Vec::with_capacity(n);
        // for k in 0..n {
        //     if k < input_rlwe_cts.len() {
        //         cts.push(input_rlwe_cts[k].clone());
        //     } else {
        //         cts.push(RLWECiphertext::allocate(self.ctx.poly_size, self.ctx.modulus));
        //     }
        // }

        // Build strided array of length N.
        let zero_ct = RLWECiphertext::allocate(self.ctx.poly_size, self.ctx.modulus);
        let mut cts: Vec<RLWECiphertext> = vec![zero_ct; n];
        for k in 0..g {
            cts[k * s] = input_rlwe_cts[k].clone();
        }

        // pack_lwes_cdks(&self.ctx, log_n, 0, &cts, subs_ksk_map)
        pack_lwes_cdks(&self.ctx, log_g, 0, &cts, subs_ksk_map)
    }

    /// Select one full original row (N coeffs) from the transposed DB.
    /// `row_rgsw_ct` = RGSW(X^{N - r*}). Returns a poly with coeff j = db[r*·N + j].
    // pub fn read_full_row_rotpack_cdks(
    //     &self,
    //     row_rgsw_ct: &RGSWCiphertext,
    //     subs_ksk_map: &HashMap<usize, RLWEKeyswitchKey>,
    // ) -> RLWECiphertext {
    //     let n = self.ctx.poly_size.0;
    //     debug_assert_eq!(self.data_enc.len(), n, "transposed DB must have exactly N polys");
    // 
    //     // rotate every transposed poly by the same r*, bringing coeff r* to position 0
    //     let mut rotated_rlwe_cts: Vec<RLWECiphertext> = Vec::with_capacity(n);
    //     for j in 0..n {
    //         rotated_rlwe_cts.push(self.rlwe_ct_rotation(&self.data_enc[j], row_rgsw_ct));
    //     }
    //     // full CDKS pack (g = N, stride = 1): input j's constant coeff -> output coeff j
    //     self.pack_first_coeffs_cdks(&rotated_rlwe_cts, subs_ksk_map)
    // }

    /// Select one full original row (N coeffs) from the transposed DB.
    /// `row_rgsw_ct` = RGSW(X^{N - r*}). Returns a poly with coeff j = db[r*·N + j].
    pub fn read_full_row_rotpack_cdks(
        &self,
        row_rgsw_ct: &RGSWCiphertext,
        subs_ksk_map: &HashMap<usize, RLWEKeyswitchKey>,
    ) -> RLWECiphertext {
        let n = self.ctx.poly_size.0;
        debug_assert_eq!(self.data_enc.len(), n, "transposed DB must have exactly N polys");
    
        // (1) transform the rotation RGSW ONCE, not per column
        let fwd_fourier = {
            let mut buf = self.ctx.gen_fft_ctx();
            row_rgsw_ct.to_fourier(&mut buf)
        };
    
        // (2) rotate every transposed poly by r* in parallel (one FFT buffer per worker)
        let ctx = &self.ctx;
        let rotated_rlwe_cts: Vec<RLWECiphertext> = self.data_enc
            .par_iter()
            .map_init(
                || ctx.gen_fft_ctx(),
                |buf, col| {
                    let mut r_j = RLWECiphertext::allocate(ctx.poly_size, ctx.modulus);
                    external_product_fourier(&mut r_j, &fwd_fourier, col, buf);
                    r_j
                },
            )
            .collect();
    
        self.pack_first_coeffs_cdks(&rotated_rlwe_cts, subs_ksk_map)
    }

    pub fn write_full_row(
        &mut self,
        fwd_rgsw: &RGSWCiphertext,
        rev_rgsw: &RGSWCiphertext,
        ct_new: &RLWECiphertext,
        lwe_rlwe_ksk: &LWEtoRLWEKeyswitchKey,
    ) {
        let n = self.ctx.poly_size.0;
        debug_assert_eq!(self.data_enc.len(), n);
        let lwe_size = LweSize(n + 1);
    
        // (1) transform each rotation RGSW ONCE, not per column
        let (fwd_fourier, rev_fourier) = {
            let mut buf = self.ctx.gen_fft_ctx();
            (fwd_rgsw.to_fourier(&mut buf), rev_rgsw.to_fourier(&mut buf))
        };
    
        // split borrows so rayon can hold data_enc mutably while we read ctx
        let ctx = &self.ctx;
        self.data_enc.par_iter_mut().enumerate().for_each_init(
            || ctx.gen_fft_ctx(),                 // one buffer per worker thread
            |buf, (j, col)| {
                // (a) forward-rotate this column: coeff r* -> position 0
                let mut r_j = RLWECiphertext::allocate(ctx.poly_size, ctx.modulus);
                external_product_fourier(&mut r_j, &fwd_fourier, &*col, buf);
    
                // (b) extract old (coeff 0 of r_j) and new (coeff j of ct_new)
                let mut old_lwe = LWECiphertext::new(lwe_size, ctx.modulus);
                old_lwe.fill_with_sample_extract(&r_j, MonomialDegree(0));
                let mut new_lwe = LWECiphertext::new(lwe_size, ctx.modulus);
                new_lwe.fill_with_sample_extract(ct_new, MonomialDegree(j));
    
                // (c) delta = new - old in the LWE domain -> ONE conversion
                for (a, b) in new_lwe.0.as_mut().iter_mut().zip(old_lwe.0.as_ref().iter()) {
                    *a = a.wrapping_sub(*b);
                }
                let delta = conv_lwe_to_rlwe(lwe_rlwe_ksk, &new_lwe, ctx);
    
                // (d) reverse-rotate: delta -> coeff r*, sign-corrected
                let mut v_j = RLWECiphertext::allocate(ctx.poly_size, ctx.modulus);
                external_product_fourier(&mut v_j, &rev_fourier, &delta, buf);
    
                // (e) add into the store
                col.update_with_add(&v_j);
            },
        );
    }

}

pub fn setup_random_oram_row_retrieval(rows: usize, cols: usize, params: TFHEParameters) -> (Client, Server, Vec<u64>) {
    let mut client = Client::new(rows, cols, params.clone());
    let neg_sk_ct = client.gen_neg_sk();
    let db = client.gen_dummy_database();

    let n = client.ctx.poly_size.0;
    let log_n = log2(n);
    let log_t = client.ctx.codec.pt_modulus_bits();
    let delta_scaled: Scalar = 1 << (Scalar::BITS as usize - log_t - log_n); // single pack => /N

    let db_enc = client.encrypt_database_transposed(&db, delta_scaled);
    let server = Server::new(db_enc, neg_sk_ct, params);
    (client, server, db)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::rlwe::compute_noise_encoded;

    #[test]
    fn test_oram() {
        let n = 16usize;
        let hash = NaiveHash::new(1, n);
        let (mut client, mut server, pts) =
            setup_random_oram(1, n,  TFHEParameters::default());
        assert_eq!(n, pts.len());

        {
            // read
            let idx = 1usize;
            let query = client.gen_read_query_one(idx, &hash);
            let y = server.process_one(query).0;
            let mut pt = client.ctx.gen_zero_pt();
            client.sk.decrypt_decode_rlwe(&mut pt, &y, &client.ctx);

            assert_eq!(pts[idx], pt);

            // check noise
            println!(
                "noise for read: {}",
                compute_noise_encoded(&client.sk, &y, &pt, &client.ctx.codec)
            );
        }

        {
            // write
            let idx = 1usize;
            let new_data = client.ctx.gen_binary_pt();
            let write_query = client.gen_write_query_one(idx, &new_data, &hash);
            server.process_one(write_query);

            let read_query = client.gen_read_query_one(idx, &hash);
            let y = server.process_one(read_query).0;
            let mut pt = client.ctx.gen_zero_pt();
            client.sk.decrypt_decode_rlwe(&mut pt, &y, &client.ctx);

            assert_eq!(new_data, pt);
        }
    }

    #[test]
    #[ignore]
    fn test_oram_more() {
        let n = 2048usize;
        let hash = NaiveHash::new(1, n);
        let (mut client, mut server, pts) =
            setup_random_oram(1, n,  TFHEParameters::default());
        assert_eq!(n, pts.len());

        for i in 0..20 {
            // read
            let idx = 1usize;
            let query = client.gen_read_query_one(idx, &hash);
            let y = server.process_one(query).0;
            let mut pt = client.ctx.gen_zero_pt();
            client.sk.decrypt_decode_rlwe(&mut pt, &y, &client.ctx);

            assert_eq!(pts[idx], pt);

            // check noise
            println!(
                "noise for read at iter {}: {}",
                i,
                compute_noise_encoded(&client.sk, &y, &pt, &client.ctx.codec)
            );
        }
    }

    #[test]
    fn test_oram_multi() {
        let n = 16usize;
        let hash = NaiveHash::new(1, n);
        let (mut client, mut server, pts) =
            setup_random_oram(1, n, TFHEParameters::default());
        assert_eq!(n, pts.len());

        {
            // read
            let idx1 = 1usize;
            let idx2 = 2usize;
            let queries = vec![
                client.gen_read_query_one(idx1, &hash),
                client.gen_read_query_one(idx2, &hash),
            ];
            let ys = server.process_multi(queries).0;

            {
                let mut pt = client.ctx.gen_zero_pt();
                client.sk.decrypt_decode_rlwe(&mut pt, &ys[0], &client.ctx);
                assert_eq!(pts[idx1], pt);
                // check noise
                println!(
                    "noise for read: {}",
                    compute_noise_encoded(&client.sk, &ys[0], &pt, &client.ctx.codec)
                );
            }

            {
                let mut pt = client.ctx.gen_zero_pt();
                client.sk.decrypt_decode_rlwe(&mut pt, &ys[1], &client.ctx);
                assert_eq!(pts[idx2], pt);
            }
        }

        {
            // write
            let idx1 = 1usize;
            let idx2 = 2usize;
            let new_data = client.ctx.gen_binary_pt();
            let write_queries = vec![
                client.gen_write_query_one(idx1, &new_data, &hash),
                client.gen_write_query_one(idx2, &new_data, &hash),
            ];
            server.process_multi(write_queries);

            let read_queries = vec![
                client.gen_read_query_one(idx1, &hash),
                client.gen_read_query_one(idx2, &hash),
            ];
            let ys = server.process_multi(read_queries).0;

            {
                let mut pt = client.ctx.gen_zero_pt();
                client.sk.decrypt_decode_rlwe(&mut pt, &ys[0], &client.ctx);
                assert_eq!(new_data, pt);
                // check noise
                println!(
                    "noise for write: {}",
                    compute_noise_encoded(&client.sk, &ys[0], &pt, &client.ctx.codec)
                );
            }

            {
                let mut pt = client.ctx.gen_zero_pt();
                client.sk.decrypt_decode_rlwe(&mut pt, &ys[1], &client.ctx);
                assert_eq!(new_data, pt);
            }
        }
    }

    #[test]
    fn test_oram_batch() {
        let n = 16usize;
        let h_count = 4usize;
        let rows = 8usize;
        let cols = h_count * n / rows;
        let hash = NaiveHash::new(h_count, n);
        let (mut client, mut server, pts) =
            setup_random_oram(rows, cols, TFHEParameters::default());
        assert_eq!(n, pts.len());

        {
            // read
            let indices = vec![0usize, 1usize];
            let mapping = hash.hash_to_mapping(&indices, cols);
            let query = client.gen_read_query_batch(&indices, &hash);
            let ys = server.process_batch(query, &hash).0;

            let mut pt = client.ctx.gen_zero_pt();
            let mut noise_checked = false;
            for (r, (_, i)) in mapping {
                client.sk.decrypt_decode_rlwe(&mut pt, &ys[r], &client.ctx);
                assert_eq!(pts[indices[i]], pt);

                // check noise
                if !noise_checked {
                    println!(
                        "noise for read: {}",
                        compute_noise_encoded(&client.sk, &ys[r], &pt, &client.ctx.codec)
                    );
                    noise_checked = true;
                }
            }
        }

        {
            // write
            let indices = vec![1usize, 2usize];
            let mapping = hash.hash_to_mapping(&indices, cols);
            let new_data = client.ctx.gen_binary_pt();
            let write_query = client.gen_write_query_batch(&indices, &new_data, &hash);
            server.process_batch(write_query, &hash);

            let read_query = client.gen_read_query_batch(&indices, &hash);
            let ys = server.process_batch(read_query, &hash).0;
            let mut pt = client.ctx.gen_zero_pt();
            for (r, _) in mapping {
                client.sk.decrypt_decode_rlwe(&mut pt, &ys[r], &client.ctx);
                assert_eq!(new_data, pt);
            }

            // additionally check the database is consistent
            for i in indices {
                for h in 0..h_count {
                    let (r, c) = hash.hash_to_tuple(h, i, cols);
                    client.sk.decrypt_decode_rlwe(
                        &mut pt,
                        &server.data[r].clone().read().unwrap()[c],
                        &client.ctx,
                    );
                    assert_eq!(new_data, pt);
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn test_oram_batch_more() {
        let h_count = 3usize;
        let rows = 3;
        let cols = 1024;
        let n = rows * cols / h_count;
        let hash = NaiveHash::new(h_count, n);

        let setup_time = Instant::now();
        let (mut client, mut server, pts) =
            setup_random_oram(rows, cols, TFHEParameters::default());
        println!("DB Setup Time: {}s\t", setup_time.elapsed().as_secs_f64());

        assert_eq!(n, pts.len());
        for iter in 0..20 {
            // read
            let indices = vec![0usize, 1usize];
            let mapping = hash.hash_to_mapping(&indices, cols);
            let query = client.gen_read_query_batch(&indices, &hash);

            let server_process = Instant::now();
            let ys = server.process_batch(query, &hash).0;
            print!(
                "server processing time: {}s\t",
                server_process.elapsed().as_secs_f64()
            );

            let mut pt = client.ctx.gen_zero_pt();
            let mut noise_checked = false;
            for (r, (_, i)) in mapping {
                client.sk.decrypt_decode_rlwe(&mut pt, &ys[r], &client.ctx);
                assert_eq!(pts[indices[i]], pt);

                // check noise
                if !noise_checked {
                    println!(
                        "noise for read at iteration {}: {}",
                        iter,
                        compute_noise_encoded(&client.sk, &ys[r], &pt, &client.ctx.codec)
                    );
                    noise_checked = true;
                }
            }
        }
    }
}
