pub mod merkletreetest;
pub mod utils;

pub mod common;
use common::*; 
pub  use ark_ed_on_bn254::EdwardsProjective as JubJub;

// #[cfg(feature="bls12_381")]
// pub mod poseidon_zk_param_bls12_381;
// #[cfg(feature="bls12_381")]
// pub use poseidon_zk_param_bls12_381::*;
#[cfg(feature="bls12_381")]
use ark_bls12_381::Bls12_381;
#[cfg(feature="bls12_381")]
pub type CurveTypeG = Bls12_381;
#[cfg(feature="bls12_381")]
pub use ark_bls12_381::*;

// #[cfg(feature="bls12_377")]
// pub mod poseidon_zk_param_bls12_377;
// #[cfg(feature="bls12_377")]
// pub use poseidon_zk_param_bls12_377::*;
#[cfg(feature="bls12_377")]
use ark_bls12_377::Bls12_377;
#[cfg(feature="bls12_377")]
pub type CurveTypeG = Bls12_377;
#[cfg(feature="bls12_377")]
pub use ark_bls12_377::*;

// #[cfg(feature="bn254c")]
// pub mod poseidon_zk_param_bn254;
// #[cfg(feature="bn254c")]
// pub use poseidon_zk_param_bn254::*;
#[cfg(feature="bn254c")]
use ark_bn254::Bn254;
#[cfg(feature="bn254c")]
pub type CurveTypeG= Bn254;
#[cfg(feature="bn254c")]
pub use ark_bn254::*;

use ark_crypto_primitives::{Path, crh::TwoToOneCRH};
/// The root of the account Merkle tree.
pub type Root = <TH as TwoToOneCRH>::Output;

/// A membership proof for a given leaf.
pub type MembPath = Path<MyMerkleTreeParams>;

#[allow(unused)]
pub static SIZEOFOUTPUT: usize = 2;
pub  const  SIZEOFINPUT: usize = 64;

