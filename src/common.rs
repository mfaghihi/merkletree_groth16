use ark_crypto_primitives::CRH;
use ark_crypto_primitives::crh::TwoToOneCRH;
//use ark_crypto_primitives::crh::pedersen::constraints::{CRHGadget,CRHParametersVar};
use ark_crypto_primitives::crh::constraints::{CRHGadget, TwoToOneCRHGadget};
// use ark_crypto_primitives::crh::injective_map::constraints::{
//     PedersenCRHCompressorGadget, TECompressorGadget,
// };
use ark_crypto_primitives::crh::{
    //injective_map::{PedersenCRHCompressor, TECompressor},
    pedersen,
};
use ark_crypto_primitives::merkle_tree::Config;
use ark_ed_on_bls12_381::{constraints::EdwardsVar};

use crate::{JubJub, MembPath, Root};

//pub type TwoToOneHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;
#[derive(Clone, PartialEq, Eq, Hash)]
    pub struct Window4x256;
    impl pedersen::Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    pub type H = pedersen::CRH<JubJub, Window4x256>;
    
    #[derive(Clone, PartialEq, Eq, Hash)]
    pub struct Window4x128;

    impl pedersen::Window for Window4x128 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 128;
    }
    pub type TH = pedersen::CRH<JubJub, Window4x128>;

    #[derive(Clone)]

    pub struct MyMerkleTreeParams;

    impl Config for MyMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = TH;
    }

    pub struct MerkleTreeVerification {
        // These are constants that will be embedded into the circuit
        pub leaf_crh_params: <H as CRH>::Parameters,
        pub two_to_one_crh_params: <TH as TwoToOneCRH>::Parameters,
    
        // This is the public input to the circuit.
        pub root: Root,
   
        // These are the private witnesses to the circuit.
        pub leaf: u8,
        pub authentication_path: Option<MembPath>,
    }

pub type TwoToOneHashGadget = pedersen::constraints::CRHGadget<
JubJub, 
EdwardsVar, 
Window4x128>;

pub type LeafHashGadget = pedersen::constraints::CRHGadget<
JubJub, 
EdwardsVar, 
Window4x256>;

pub type LeafHashParamsVar = <LeafHashGadget as CRHGadget<H, ConstraintF>>::ParametersVar;
pub type TwoToOneHashParamsVar =
    <TwoToOneHashGadget as TwoToOneCRHGadget<TH, ConstraintF>>::ParametersVar;

pub type ConstraintF = ark_ed_on_bn254::Fq;
