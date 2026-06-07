#![allow(unused)]

use crate::{
    context::{Context, FftBuffer},
    decision_tree::{bit_decomposed_rgsw, demux_with},
    naive_hash::NaiveHash,
    num_types::{One, Scalar, Zero},
    params::TFHEParameters,
    lwe::{LWEtoRLWEKeyswitchKey, LWECiphertext, conv_lwe_to_rlwe},
    rgsw::RGSWCiphertext,
    rlwe::{decomposed_rlwe_to_rgsw, RLWECiphertext, RLWESecretKey},
    utils::pt_to_lossy_u64,
    utils::{transpose, log2},
};
use rand::Rng;

use tfhe::{
    core_crypto::entities::plaintext::Plaintext,
    core_crypto::entities::plaintext_list::PlaintextList,
};

use rayon::prelude::*;
use std::{
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

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

    // Generate a dummy database for performance testing.
    // pub fn gen_dummy_database(&mut self) -> (Vec<PlaintextList<Vec<Scalar>>>, Vec<Vec<RLWECiphertext>>) {
    pub fn gen_dummy_database(&mut self) -> Vec<u64> {
        // TODO put NaiveHash in Client struct
        println!("\nCreating dummy database for performace testing");
        let item_count = self.rows * self.cols;
        println!("\n(line125_oram.rs): Ciphertext modulus:{:?}",self.ctx.modulus);
        // println!("\nTotal data elements in the database is:{:?}",item_count);
        let mut db = vec![item_count];

        //Define maximum value of database element
        let max_db_element:u64=self.ctx.codec.pt_modulus(); // 128;  //150500;
        println!("Plaintext mod:{:?}",max_db_element);

        // Create a database vector
        let mut db: Vec<u64> = Vec::with_capacity(item_count);

        //create encrypted data vector
        // let mut enc_db: Vec<RLWECiphertext> = Vec::with_capacity(item_count);

        // create random elements and inser it into the database
        let mut i=0;
        while item_count>i {
            let data_item=rand::thread_rng().gen_range(0..max_db_element);
            
            // let data_item = (i as u64) % 32;
            // let data_item = (i as u64) % max_db_element;

            db.push(data_item);
            i+=1;            
        }
        db
    }

    pub fn decrypt_final_result(& mut self, query:RLWECiphertext) -> PlaintextList<Vec<u64>> {

        let mut pt = self.ctx.gen_zero_pt();
        // println!("\nHere is the value of query:{:?}",query);
        // self.sk.decrypt_rlwe(&mut pt, &query); 
        //when encrypted with a mentioned encoding
        self.sk.decrypt_decode_rlwe(&mut pt, &query, &mut self.ctx);
        pt
    }

}

pub struct Server {
    data: Vec<u64>,
    neg_s: RGSWCiphertext,
    ctx: Context,
}

impl Server {
    /// Create a new server that stores ciphertexts `data`.
    pub fn new(
        data: Vec<u64>,
        neg_s: RGSWCiphertext,
        params: TFHEParameters,
    ) -> Self {
        Self {
            data: data,
                // .into_iter()
                // .map(|row| Arc::new(RwLock::new(row)))
                // .collect(),
            neg_s,
            ctx: Context::new(params),
        }
    }

    fn rows(&self) -> usize {
        self.data.len()
    }

    fn cols(&self) -> usize {
        // self.data[0].clone().read().unwrap().len()
        self.data.clone().len()
    }

    // applying rotation on the packed ciphertext with RGSW ciphertext as rotation polynomial
    pub fn rotation_stage2(
        &mut self,
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

    // apurba — packing via sample extraction + LWE-to-RLWE keyswitch.
    // For each rot_stage1_cts[k], extract m_k[0] as LWE, switch back to RLWE,
    // shift to position k via X^k, and sum 
    // Output: RLWE encryption of (m_0[0], m_1[0], ..., m_{N-1}[0]).
    pub fn pack_first_coeffs_lwe(
        &self,
        rot_stage1_cts: &[RLWECiphertext],
        lwe_to_rlwe_ksk: &LWEtoRLWEKeyswitchKey,
    ) -> RLWECiphertext {
        assert!(!rot_stage1_cts.is_empty(), "no stage-1 ciphertexts to pack");
        let n = self.ctx.poly_size.0;
        assert!(
            rot_stage1_cts.len() <= n,
            "can pack at most poly_size constant terms; got {}",
            rot_stage1_cts.len()
        );
    
        let mut acc = RLWECiphertext::allocate(self.ctx.poly_size, self.ctx.modulus);
    
        for (k, ct) in rot_stage1_cts.iter().enumerate() {
            // Sample-extract the constant term as an LWE ciphertext (encrypts m_k[0] · Δ)
            let mut lwe_ct = LWECiphertext::new(self.ctx.lwe_size(), self.ctx.modulus);
            lwe_ct.fill_with_const_sample_extract(ct);
    
            // LWE to RLWE: result decrypts to (m_k[0]·Δ, 0, ..., 0)
            let mut rlwe_k = conv_lwe_to_rlwe(lwe_to_rlwe_ksk, &lwe_ct, &self.ctx);
    
            // Multiply by X^k to shift the constant term to position k
            if k > 0 {
                let mut x_k = self.ctx.gen_zero_pt();
                // x_k.as_mut_polynomial().get_mut_monomial(MonomialDegree(k)).set_coefficient(Scalar::one());
                x_k.as_mut()[k] = Scalar::one();
                rlwe_k.update_mask_with_mul_with_buf(&x_k.as_polynomial());
                rlwe_k.update_body_with_mul_with_buf(&x_k.as_polynomial());
            }
    
            // Accumulate
            acc.update_with_add(&rlwe_k);
        }
    
        acc
    }

    pub fn multi_stage_rotation_computation_samp_ext_lwe_rlwe_ks(
        &mut self,
        database: Vec<u64>,
        idx_ct_rlwe_stage1: RLWECiphertext,
        idx_ct_rgsw_stage2: RGSWCiphertext,
        lsb_bits: usize,
        msb_bits: usize,
        lwe_to_rlwe_ksk: &LWEtoRLWEKeyswitchKey,
    ) -> RLWECiphertext {
        let coeff_per_poly  = 1 << lsb_bits;
        let num_polynomials = 1 << msb_bits;
    
        let mut rot_stage1_cts: Vec<RLWECiphertext> = vec![];
        for poly_idx in 0..num_polynomials {
            let mut poly_data = self.ctx.gen_zero_pt();
            for coeff_idx in 0..coeff_per_poly {
                let db_idx = poly_idx * coeff_per_poly + coeff_idx;
                let mut value = database[db_idx];
                // poly_data.as_mut_polynomial().get_mut_monomial(MonomialDegree(coeff_idx)).set_coefficient(value);
                poly_data.as_mut()[coeff_idx] = value;
            }
    
            let mut rot1_result = idx_ct_rlwe_stage1.clone();
            rot1_result.update_mask_with_mul_with_buf(& poly_data.as_polynomial());
            rot1_result.update_body_with_mul_with_buf(& poly_data.as_polynomial());
            
            // let mut poly_data_mut = poly_data.clone();
            // rot1_result.update_mask_with_mul(& poly_data_mut.as_mut_polynomial());
            // rot1_result.update_body_with_mul(& poly_data_mut.as_mut_polynomial());
    
            rot_stage1_cts.push(rot1_result);        
        }
    
        // pack the stage-1 constant terms into a single RLWE ciphertext
        let packed = self.pack_first_coeffs_lwe(&rot_stage1_cts, lwe_to_rlwe_ksk);
    
        let result = self.rotation_stage2(&packed, &idx_ct_rgsw_stage2);
    
        // packed
        result
    }

}

// Setup the ORAM client and server for experimentation.
pub fn setup_random_oram(rows: usize, cols: usize, params: TFHEParameters,) -> (Client, Server, Vec<u64>) {

    //initialize client
    let mut client = Client::new(rows, cols, params.clone());
    
    //create negative of secret key and encrypt it 
    let neg_sk_ct = client.gen_neg_sk();
    
    //Generate a dummy database vectors and encryt them
    let db = client.gen_dummy_database();

    //initialize server
    let server = Server::new(db.clone(), neg_sk_ct, params);

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
