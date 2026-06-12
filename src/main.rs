#![allow(unused)]
use rand::Rng;
use std::process;
use clap::Parser;
use panacea::{
    cli::Cli, 
    naive_hash::NaiveHash, 
    num_types::Scalar, 
    oram::{setup_random_oram_row_retrieval, Client, Server, PackOfflineData, gen_fixed_mask, negacyclic_mul}, 
    params::{ORAMParameters, ServerParams, TFHEParameters, MASK_SEED}, 
    rlwe::{compute_noise_encoded, RLWECiphertext, gen_all_subs_ksk, gen_all_subs_ksk_fourier, RLWEKeyswitchKey},
    rgsw::RGSWCiphertext,
    utils::log2
};
use std::{fs::File, io::BufReader, time::Instant, collections::HashMap};
use panacea::lwe::{LWESecretKey, LWEtoRLWEKeyswitchKey};
use tfhe::core_crypto::commons::math::random::{UniformBinary, UniformTernary};

fn single_query(item_count: usize, iterations: usize, tfhe_params: TFHEParameters, dryrun: bool) {
    assert!(iterations > 0);
    println!("Database size, item_count: {item_count}, \nNumber of bits required to represent database size: {}", log2(item_count));
    if !dryrun {

        // Useful prints:
        // apd
        println!("\nUSEFUL PRINTS - abc");
        println!("polynomial_size: {}", tfhe_params.polynomial_size);
        println!("plaintext_modulus: {}", tfhe_params.plaintext_modulus);
        println!("poly_size_bit_length: {}", log2(tfhe_params.polynomial_size));

        // println!("\n\nMod value q:{:?}",Scalar::BITS);
        let setup_instant = Instant::now();
        // let (mut client, mut server, pln_db) = setup_random_oram(1, item_count, /* &NaiveHash, */ tfhe_params.clone());
        let (mut client, mut server, mut db) = setup_random_oram_row_retrieval(1, item_count, tfhe_params.clone());

        let setup_duration = setup_instant.elapsed().as_secs_f64();
        println!("\nSetup and database creation time: {} sec.",setup_duration);

        let n = client.ctx.poly_size.0;
        let m = item_count / n;
        let log_t = client.ctx.codec.pt_modulus_bits();
        let log_n = log2(n);
        
        let subs_ksk_map = gen_all_subs_ksk(&client.sk, &mut client.ctx); // apd - TODO: fourier version to be used?
        let row_idx: usize = rand::thread_rng().gen_range(0..m);
        println!("\nRow index in original database to fetch (full row retrieval): {row_idx}");

        println!("\nTotal database elements -------------->{:?}", item_count);
        
        // RGSW(X^{N - r*})
        let rot_deg = (n - row_idx) % n;
        let mut rot_pt = client.ctx.gen_zero_pt();
        rot_pt.as_mut()[rot_deg] = 1;
        let mut row_rgsw = RGSWCiphertext::allocate(client.ctx.poly_size, client.ctx.base_log, client.ctx.level_count, client.ctx.modulus);
        client.sk.encrypt_rgsw(&mut row_rgsw, &rot_pt, &mut client.ctx);

        let start_read_full_row_computation = Instant::now();
        let result = server.read_full_row_rotpack_cdks(&row_rgsw, &subs_ksk_map);
        println!("\nTime taken (online) - full row read: {} sec.", start_read_full_row_computation.elapsed().as_secs_f64()); 

        let dec = client.decrypt_final_result(result);
        // one rotation => whole row sign-flips iff row_idx != 0 (negacyclic X^N = -1)
        let retrieved: Vec<u64> = (0..n).map(|j| {
            let c = dec.as_ref()[j];
            if row_idx != 0 
                { c.wrapping_neg() % tfhe_params.plaintext_modulus }
            else 
                { c % tfhe_params.plaintext_modulus }
        }).collect();
        
        let expected: Vec<u64> = (0..n).map(|j| db[row_idx * n + j]).collect();

        // --- Print first/last 5 coefficients ---
        let print_coeffs = |label: &str, v: &Vec<u64>| {
            let first5: Vec<(usize, u64)> = v.iter().enumerate().take(5).map(|(i,&x)| (i,x)).collect();
            let last5:  Vec<(usize, u64)> = v.iter().enumerate().rev().take(5).rev().map(|(i,&x)| (i,x)).collect();
            println!("{} | first 5: {:?}", label, first5);
            println!("{} | last  5: {:?}", label, last5);
        };
        
        print_coeffs("expected: ", &expected);
        print_coeffs("retrieved: ", &retrieved);
        // ----------------------------------------

        assert_eq!(expected, retrieved, "Full row ORAM READ incorrect");
        println!("\n===== Full row ORAM READ correct! =====");

        // ORAM write flow
        let delta_scaled: Scalar = 1 << (Scalar::BITS as usize - log_t - log2(n)); // Δ/N, as in setup
        let t = tfhe_params.plaintext_modulus;
        
        let lwe_rlwe_ksk = client.gen_lwe_to_rlwe_ksk();
        
        // ---- WRITE ----
        let new_row_data: Vec<u64> = (0..n)
            .map(|_| rand::thread_rng().gen_range(0..client.ctx.codec.pt_modulus()))
            .collect();
        let (fwd_rgsw_query, rev_rgsw_query, ct_to_write) = client.gen_row_write_query(row_idx, &new_row_data, delta_scaled);
        
        let start_write_full_row_computation = Instant::now();
        server.write_full_row(&fwd_rgsw_query, &rev_rgsw_query, &ct_to_write, &lwe_rlwe_ksk);
        println!("\nTime taken (online) - full row write: {} sec.", start_write_full_row_computation.elapsed().as_secs_f64());
        
        for j in 0..n { db[row_idx * n + j] = new_row_data[j]; }     // mirror plaintext for the check
        
        // ---- READ-AFTER-WRITE ----
        let rot_deg = (n - row_idx) % n;
        let mut rot_pt = client.ctx.gen_zero_pt();
        rot_pt.as_mut()[rot_deg] = 1;
        let mut row_rgsw = RGSWCiphertext::allocate(client.ctx.poly_size, client.ctx.base_log, client.ctx.level_count, client.ctx.modulus);
        client.sk.encrypt_rgsw(&mut row_rgsw, &rot_pt, &mut client.ctx);
        // let start_readback_full_row_computation = Instant::now(); 
        let result = server.read_full_row_rotpack_cdks(&row_rgsw, &subs_ksk_map);
        // println!("\nTime taken (online) - full row read-back: {} sec.", start_readback_full_row_computation.elapsed().as_secs_f64());
        let dec = client.decrypt_final_result(result);
        let read_back: Vec<u64> = (0..n).map(|j| {
            let c = dec.as_ref()[j];
            if row_idx != 0 { c.wrapping_neg() % t } else { c % t }
        }).collect();
        
        assert_eq!(new_row_data, read_back, "Full row ORAM WRITE incorrect");
        
        print_coeffs("new_row_data (written): ", &new_row_data);
        print_coeffs("read_back: ", &read_back);
        // ----------------------------------------
        
        println!("\n===== Full row ORAM WRITE correct! =====");

    } else {
        println!("Inside else statement");
        println!("-,-,-,-");
    }
}

fn main() {
    let cli = Cli::parse();

    // if we have a value passed to --params, all other params from cli are ignored
    //      if it is able to read the file, it gets all parameters from there
    //      otherwise, if reading the file fails (wrong path or format), then it uses default parameters
    // otherwise, it uses parameters from cli with the preset defaults

    let input_params = match File::open(&cli.params) {
        Ok(file) => ServerParams::from_input_params_list(
            serde_json::from_reader(BufReader::new(file)).unwrap_or_default(),
        ),
        _ => vec![ServerParams {
            oram: match cli.mode {
                _ => ORAMParameters::SingleQuery {
                    item_count: cli.item_count,
                    iterations: 1,
                },
            },
            tfhe: TFHEParameters {
                standard_deviation: cli.standard_deviation,
                polynomial_size: cli.polynomial_size,
                base_log: cli.base_log,
                level_count: cli.level_count,
                key_switch_base_log: cli.key_switch_base_log,
                key_switch_level_count: cli.key_switch_level_count,
                negs_base_log: cli.negs_base_log,
                negs_level_count: cli.negs_level_count,
                plaintext_modulus: cli.plaintext_modulus,
                modulus: cli.modulus,
                secure_seed: cli.secure_seed,
            },
        }],
    };
    for params in input_params {
        println!("standard_deviation:{} \npolynomial_size:{} \nbase_log:{} \nlevel_count:{} \nkey_switch_base_log:{} \nkey_switch_level_count:{} 
        \nnegs_base_log:{} \nnegs_level_count:{} \nplaintext_modulus bits:{} \nsecure_seed:{}", 
                // \nmode:{} \nitem_count:{} \nquery_count:{} \nrows:{} \ncols:{} \nn:{} \nsetup_duration:{} \nserver_duration:{}
                // \nresponse_duration:{} \nfinal_noise:{} \n",
            params.tfhe.standard_deviation,
            params.tfhe.polynomial_size,
            params.tfhe.base_log,
            params.tfhe.level_count,
            params.tfhe.key_switch_base_log,
            params.tfhe.key_switch_level_count,
            params.tfhe.negs_base_log,
            params.tfhe.negs_level_count,
            log2(params.tfhe.plaintext_modulus as usize),
            // log2(params.tfhe.modulus),
            params.tfhe.secure_seed
        );

        match params.oram {
            ORAMParameters::SingleQuery {
                item_count,
                iterations,
            } => single_query(item_count, iterations, params.tfhe, cli.dryrun),
            _ => panic!("Only single_query mode is supported in this codebase"),
        }
        println!("Done with match function");
    }
    println!("Done with params for-loop");
}
