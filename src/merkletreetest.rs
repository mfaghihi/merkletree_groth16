#[test]
pub fn mertre(){
    use ark_crypto_primitives::crh::TwoToOneCRH;
    use ark_crypto_primitives::merkle_tree::*;
    use ark_crypto_primitives::crh::CRH;
    use crate::common::{LeafHash, MyMerkleTreeParams, TwoToOneHash};
    //use crate::common::MerkleTreeCircuit;

    use ark_std::{test_rng};

    let mut rng = test_rng();

    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap(); 
    let leaves = [0u8, 2u8, 5u8, 32u8, 3u8, 4u8, 5u8, 12u8];
    
    let  m= MerkleTree::<MyMerkleTreeParams>::new(
        &leaf_crh_params.clone(), 
        &two_to_one_crh_params.clone(), 
        &leaves)
        .unwrap();

    let proof= m.generate_proof(3).unwrap();

    let root = m.root();

    let leaf = 32u8;

    assert!(proof.verify(&leaf_crh_params, &two_to_one_crh_params, &root, &leaf).unwrap());

    // let circuit= MerkleTreeCircuit{
    //     leaf_crh_params: (leaf_crh_params.clone()),
    //     two_to_one_crh_params: (two_to_one_crh_params.clone()),
    //     root: (root.clone()),
    //     leaf: (leaf.clone()),
    //     authentication_path: Some(proof.clone()),
    // };
}