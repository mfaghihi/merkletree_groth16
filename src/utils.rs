use ark_crypto_primitives::crh::CRH;
use ark_crypto_primitives::crh::pedersen;
use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::UniformRand;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::SynthesisError;

//use ark_relations::r1cs::ConstraintSystem;
use ark_std::test_rng;
//use ark_test_curves::bls12_381::Fr;



use ark_ff::PrimeField;
use ark_crypto_primitives::SNARK;

use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::ConstraintSystem;
use ark_relations::*;
use ark_groth16::*;

use crate::*;

use ark_ed_on_bn254::EdwardsProjective as JubJub;
    use ark_ff::{BigInteger256, ToBytes};

    #[derive(Clone)]
    pub struct Window4x256;
    impl pedersen::Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = pedersen::CRH<JubJub, Window4x256>;
    
    struct JubJubMerkleTreeParams;

    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;
    }

