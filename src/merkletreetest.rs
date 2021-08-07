use ark_crypto_primitives::MerkleTree;
use ark_crypto_primitives::crh::{TwoToOneCRH, pedersen};
use ark_crypto_primitives::merkle_tree::*;

//use ark_crypto_primitives::crh::pedersen::*;
//use ark_ff::UniformRand;
use ark_crypto_primitives::crh::CRH;

use crate::common::{H,TH,MyMerkleTreeParams};


#[test]
pub fn mertre(){
    
    //use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    //use ark_ed_on_bn254::EdwardsProjective as JubJub;

    use ark_ff::{BigInteger256, ToBytes};
    use ark_std::{test_rng};

    
    //type MyMerkleTree=MerkleTree::<MyMerkleTreeParams>;
    let mut rng = test_rng();

    let leaf_crh_params = <H as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <H as TwoToOneCRH>::setup(&mut rng).unwrap(); 
    let leaves = ark_ff::to_bytes!(vec!([0u8, 2u8, 5u8, 32u8, 3u8, 4u8, 5u8, 12u8])).unwrap();
    
    let mut m= MerkleTree::<MyMerkleTreeParams>::new(
        &leaf_crh_params.clone(), 
        &two_to_one_crh_params.clone(), 
        &leaves)
        .unwrap();

    let proof= m.generate_proof(3).unwrap();

    let root = m.root();

    let leaf = 32u8;

    assert!(proof.verify(&leaf_crh_params, &two_to_one_crh_params, &root, &leaf).unwrap());
    m.update(2, &leaf).unwrap();
}