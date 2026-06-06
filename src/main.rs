#![allow(unused)]
use rand::Rng;
use std::process;
use clap::Parser;
use panacea::{
    cli::Cli, 
    naive_hash::NaiveHash, 
    num_types::Scalar, 
    oram::{setup_random_oram, Client, Server}, 
    params::{ORAMParameters, ServerParams, TFHEParameters}, 
    rlwe::{compute_noise_encoded, RLWECiphertext},
    rgsw::RGSWCiphertext,
    utils::log2
};
use std::{fs::File, io::BufReader, time::Instant};
use panacea::lwe::{LWESecretKey, LWEtoRLWEKeyswitchKey};

fn single_query(item_count: usize, iterations: usize, tfhe_params: TFHEParameters, dryrun: bool) {
    assert!(iterations > 0);
    println!("Database size, item_count: {item_count}, \nNumber of bits required to represent database size: {}", log2(item_count));
    if !dryrun {

        // Useful prints:
        // apurba
        println!("\nUSEFUL PRINTS - APURBA");
        println!("polynomial_size: {}", tfhe_params.polynomial_size);
        println!("plaintext_modulus: {}", tfhe_params.plaintext_modulus);
        println!("poly_size_bit_length: {}", log2(tfhe_params.polynomial_size));

        //apurba
        let lsb_bits_rot = log2(tfhe_params.polynomial_size);
        let msb_bits_rot = log2(item_count) - lsb_bits_rot;

        // println!("\n\nMod value q:{:?}",Scalar::BITS);
        let setup_instant = Instant::now();
        let (mut client, mut server, pln_db) =
            setup_random_oram(1, item_count, /* &NaiveHash, */ tfhe_params.clone());

        let setup_duration = setup_instant.elapsed().as_secs_f64();
        println!("\nSetup and database creation time:{} sec.",setup_duration);

        // Useful prints:
        // apurba
        println!("\nUSEFUL PRINTS - APURBA");
        println!("client.ctx.poly_size.0: {}", client.ctx.poly_size.0);
        println!("client.ctx.codec.pt_modulus(): {}", client.ctx.codec.pt_modulus());

        //Generate a random database index from a total of item_count number of rows.
        let db_rows: u64 = item_count as u64;

        // Generate a random index to fetch data from
        
        // let idx:usize = rand::thread_rng().gen_range(0..item_count);//item_count); //db_rows
        // let idx = 2048; // msb index = 1, lsb index = 0
        // let idx = 2129; // msb index = 1, lsb index = 81
        // let idx = 5; // msb index = 0, lsb index = 5
        let idx = 0; // msb index = 0, lsb index = 0

        println!("\nTotal database elements -------------->{:?}",db_rows);
        println!("\nDatabase index to be read ------>{:?}",idx);

        let query_lsb_value = idx & ((1 << lsb_bits_rot) - 1);
        let query_msb_value = idx >> lsb_bits_rot;


        // apurba
        // Generate key switching keys needed for the RLWE to RGSW decomposition operation to carry out.
        // let ksk_map =client.generate_ksk();

        //Generate key switching keys needed for the RLWE to RGSW decomposition operation to carry out.
        //This key is sent/available to server to convert RLWE ciphetext to RGSW ciphertext in fourier domain
        
        // let ksk_map =client.generate_ksk_fourier();
        
        let n = client.ctx.poly_size.0;
        // let k = query_lsb_value;
        let rot_deg_stage1 = (n - query_lsb_value) % n; // % n fix - to fix degree 2048 out of range error
        let rot_deg_stage2 = (n - query_msb_value) % n;

        let mut rot_poly_pt_stage1 = client.ctx.gen_zero_pt();
        // rot_poly_pt_stage1.as_mut_polynomial().get_mut_monomial(MonomialDegree(rot_deg_stage1)).set_coefficient(1);
        rot_poly_pt_stage1.as_mut()[rot_deg_stage1] = 1;

        let mut rot_poly_pt_stage2 = client.ctx.gen_zero_pt();
        // rot_poly_pt_stage2.as_mut_polynomial().get_mut_monomial(MonomialDegree(rot_deg_stage2)).set_coefficient(1);
        rot_poly_pt_stage2.as_mut()[rot_deg_stage2] = 1;
       
        let mut rot_poly_ct_rlwe_stage1 = RLWECiphertext::allocate(client.ctx.poly_size, client.ctx.modulus);
        let mut rot_poly_ct_rgsw_stage2 = RGSWCiphertext::allocate(client.ctx.poly_size, client.ctx.base_log, client.ctx.level_count, client.ctx.modulus);
        
        // sample-extract_lwe-rlwe-keyswitch 
        // generation of LWE secret key (binary coefficients)
        // let lwe_sk = LWESecretKey::generate_binary(client.ctx.lwe_dim(), &mut client.ctx.secret_generator,);
        let lwe_sk = LWESecretKey::generate_new_binary(client.ctx.lwe_dim(), &mut client.ctx.secret_generator);
        // deriving the RLWE SK from LWE SK - same coefficients, RLWE container
        let rlwe_sk = lwe_sk.to_rlwe_sk();
        client.sk = rlwe_sk;
        // LWE-to-RLWE keyswitch key
        let mut lwe_to_rlwe_ksk = LWEtoRLWEKeyswitchKey::allocate(&client.ctx);
        lwe_to_rlwe_ksk.fill_with_keyswitching_key(&lwe_sk, &mut client.ctx);

        // --- conv_lwe_to_rlwe round-trip sanity check ---
        {
            use panacea::lwe::{LWECiphertext, conv_lwe_to_rlwe};
            // known plaintext: constant term = 42
            let mut pt = client.ctx.gen_zero_pt();
            pt.as_mut()[0] = 42;
        
            let mut rlwe_in = RLWECiphertext::allocate(client.ctx.poly_size, client.ctx.modulus);
            client.sk.encode_encrypt_rlwe_binary(&mut rlwe_in, &pt, &mut client.ctx);
        
            // sample-extract the constant coeff -> LWE under lwe_sk
            let mut lwe_ct = LWECiphertext::new(client.ctx.lwe_size(), client.ctx.modulus);
            lwe_ct.fill_with_const_sample_extract(&rlwe_in);
        
            // switch back to RLWE under client.sk, decrypt
            let rlwe_out = conv_lwe_to_rlwe(&lwe_to_rlwe_ksk, &lwe_ct, &client.ctx);
            let mut dec = client.ctx.gen_zero_pt();
            client.sk.decrypt_decode_rlwe(&mut dec, &rlwe_out, &mut client.ctx);
            println!("conv round-trip: expected 42, got {}", dec.as_ref()[0]);
        }


        let encode_encr_rot_poly = Instant::now();
        // client.sk.encode_encrypt_rlwe(&mut rot_poly_ct_rlwe_stage1, &rot_poly_pt_stage1, &mut client.ctx);
        client.sk.encode_encrypt_rlwe_binary(&mut rot_poly_ct_rlwe_stage1, &rot_poly_pt_stage1, &mut client.ctx);
        
        // let mut rot_poly_pt_stage2_encoded = rot_poly_pt_stage2.clone();
        // client.ctx.codec.poly_encode(&mut rot_poly_pt_stage2_encoded.as_mut_polynomial());
        // client.sk.encrypt_rgsw(&mut rot_poly_ct_rgsw_stage2, &rot_poly_pt_stage2_encoded, &mut client.ctx);

        client.sk.encrypt_rgsw(&mut rot_poly_ct_rgsw_stage2, &rot_poly_pt_stage2, &mut client.ctx); // working
        let encode_encr_rot_poly_duration = encode_encr_rot_poly.elapsed().as_secs_f64();    
        println!("\nTime required for encode_encrypt of rotation polynomials:{} sec.", encode_encr_rot_poly_duration);


        // apurba - ks_packing updates
        // generate enc_sk = RLWE_s(s)
        // let mut enc_sk = RLWECiphertext::allocate(client.ctx.poly_size);
        // client.sk.encrypt_sk_as_rlwe(&mut enc_sk, &mut client.ctx);
        
        let db_copy=pln_db.clone();
        // let ct_gsw1=ct_gsw.clone();
        // println!("\n\nDatabase contains elements:{:?}",pts);
        // let rotation_sk = client.ctx.gen_rlwe_sk();


        println!("\nMain computation in the encrypted domain started");
        let enc_data_comp = Instant::now();

        // let result = server.rotation_and_cmux_computation(pln_db, query_rgsw_ct_cmux, rot_poly_ct_rlwe_stage1, lsb_bits_rot, msb_bits_cmux);
        let result = server.multi_stage_rotation_computation_samp_ext_lwe_rlwe_ks(pln_db.clone(), rot_poly_ct_rlwe_stage1.clone(), rot_poly_ct_rgsw_stage2.clone(), lsb_bits_rot, msb_bits_rot, &lwe_to_rlwe_ksk);

        // println!("Here is the computed result:{:?}", result);
        let total_enc_index_comp_time = enc_data_comp.elapsed().as_secs_f64();   
        println!("\nTotal time required for main computation to be carried out in the enc domain:{} sec.",total_enc_index_comp_time);


        //Decrypt and check the result for correctness

        // let mut dec1 = client.ctx.gen_zero_pt();
        // rotation_sk.decrypt_decode_rlwe(&mut dec1, &result, &client.ctx);
      
        // decryption - degree 2048 out of range fix version
        let dec1 = client.decrypt_final_result(result);
        // let result_poly = dec1.as_polynomial();
        let coeff0 = dec1.as_ref()[0];

        // %n fix - to fix degree 2048 out of range error
        // let retrieved_value = if ((query_lsb_value == 0) ^ (query_msb_value == 0)) {result_poly.coefficient_iter().nth(0).unwrap().wrapping_neg() % tfhe_params.plaintext_modulus} else {result_poly.coefficient_iter().nth(0).unwrap() % tfhe_params.plaintext_modulus};
        let retrieved_value = if ((query_lsb_value==0) ^ (query_msb_value==0)) {coeff0.wrapping_neg() % tfhe_params.plaintext_modulus}
                              else {coeff0 % tfhe_params.plaintext_modulus};


        println!("\n\nPlaintext data in the mentioned database index:{:?}",db_copy[idx]);
        println!("\nDecrypted query:{:?}", retrieved_value);

        // for debug
        // println!("\nresult_poly.coefficient_iter().nth(0).unwrap(): {:?}", result_poly.coefficient_iter().nth(0).unwrap());
        // println!("\nresult_poly.coefficient_iter().nth(0): {:?}", result_poly.coefficient_iter().nth(0));

        // println!("\nDecrypted query is:{:?}",dec1);
        // println!("\nDecrypted query is:{:?}",dec1.plaintext_iter().nth(0));
        // println!("\nEncrypted domain computation and obtained result is:{:?}",dec1.as_mut_polynomial().get_monomial(MonomialDegree(0)));// .as_polynomial().get_monomial(0));

        // apurba
        if (db_copy[idx] == retrieved_value) {
            println!("\nPIR result correct!");
        } else {
            println!("\nPIR result wrong!");
        }

    } else {
        println!("Inside else statement");
        println!("-,-,-,-");
    }
}

fn main() {
    // Parameters from SEAL PIR: https://eprint.iacr.org/2017/1142.pdf
    // n = 2^20
    // k = 256
    // b = 1.5k = 384
    // w = 3
    // every row (bucket) in the database has 3*n / b = 2^13 elements
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
    // println!(
    //     "standard_deviation:\npolynomial_size::{} \nbase_log:{} \nlevel_count:{} \nkey_switch_base_log:{} \nkey_switch_level_count:{} \nnegs_base_log:{} \nnegs_level_count:{} \nplaintext_modulus:{} \nsecure_seed:{} \nmode:{} \nitem_count:{} \nquery_count:{} \nrows:{} \ncols:{} \nn:{} \nsetup_duration:{} \nserver_duration:{} \nresponse_duration:{} \nfinal_noise:{} \n");
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
    println!("Done with params");
}
