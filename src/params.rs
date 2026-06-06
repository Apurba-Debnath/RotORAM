use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TFHEParameters {
    pub standard_deviation: f64,
    pub polynomial_size: usize,
    pub base_log: usize,
    pub level_count: usize,
    pub key_switch_base_log: usize,
    pub key_switch_level_count: usize,
    pub negs_base_log: usize,
    pub negs_level_count: usize,
    pub plaintext_modulus: u64,
    pub secure_seed: bool,

    // abheet: new field added!
    pub modulus: u128,
}

impl Default for TFHEParameters {
    fn default() -> Self {
        Self {
            standard_deviation: -55.0,
            polynomial_size: 2048,
            base_log: 5,
            level_count: 6,
            key_switch_base_log: 5,
            key_switch_level_count: 9,
            negs_base_log: 5,
            negs_level_count: 9,
            plaintext_modulus: 1 << 8,
            secure_seed: true,

            // abheet: new field added in default parameters, it defaults to 
            // the 64 bit native modulus.
            // modulus: 2u64.pow(64) as u128,
            modulus: 1u128 << 64
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ORAMParameters {
    SingleQuery {
        item_count: usize,
        iterations: usize,
    },
    MultiQuery {
        item_count: usize,
        query_count: usize,
        iterations: usize,
    },
    Batched {
        rows: usize,
        cols: usize,
        iterations: usize,
    },
}

impl Default for ORAMParameters {
    fn default() -> Self {
        Self::Batched {
            rows: 384,
            cols: 16,
            iterations: 1,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct InputParamsList {
    pub list: Vec<(Vec<ORAMParameters>, Vec<TFHEParameters>)>,
}

impl Default for InputParamsList {
    fn default() -> Self {
        Self {
            list: vec![(
                vec![ORAMParameters::default()],
                vec![TFHEParameters::default()],
            )],
        }
    }
}

pub struct ServerParams {
    pub oram: ORAMParameters,
    pub tfhe: TFHEParameters,
}

impl Default for ServerParams {
    fn default() -> Self {
        Self {
            oram: ORAMParameters::default(),
            tfhe: TFHEParameters::default(),
        }
    }
}

impl ServerParams {
    pub fn from_input_params_list(input: InputParamsList) -> Vec<Self> {
        let mut out: Vec<Self> = Vec::new();
        for x in input.list {
            for x_oram in &x.0 {
                for x_tfhe in &x.1 {
                    out.push(Self {
                        oram: x_oram.clone(),
                        tfhe: x_tfhe.clone(),
                    })
                }
            }
        }
        out
    }
}
