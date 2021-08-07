use ark_crypto_primitives::MerkleTree;
use ark_crypto_primitives::crh::CRH;
use ark_crypto_primitives::crh::TwoToOneCRHGadget;

use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::SynthesisError;

use ark_std::rand::SeedableRng;
use ark_std::test_rng;

use ark_crypto_primitives::SNARK;
use ark_r1cs_std::prelude::*;
use ark_groth16::*;
use rand_chacha::ChaCha20Rng;

use crate::*;
use ark_crypto_primitives::merkle_tree::constraints::PathVar;

pub type RootVar = <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::OutputVar;
pub type SimplePathVar =
    PathVar<MyMerkleTreeParams,
        LeafHashGadget,
        TwoToOneHashGadget,
        ConstraintF>;

impl ConstraintSynthesizer<ConstraintF> for MerkleTreeCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // First, we allocate the public inputs
        let root = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;

        let leaf = UInt8::new_witness(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf))?;

        // Then, we allocate the public parameters as constants:
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // Finally, we allocate our path as a private witness variable:
        let path = SimplePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
            Ok(self.authentication_path
                .as_ref()
                .unwrap())
        })?;

        let leaf_bytes = vec![leaf; 1];
        let leaf_g :&[_] =leaf_bytes.as_slice();
        // Now, we have to check membership. How do we do that?
        // Hint: look at https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/constraints.rs#L135

        // TODO: FILL IN THE BLANK!
         let is_member = path.verify_membership(
             &leaf_crh_params, 
             &two_to_one_crh_params, 
             &root, 
             &leaf_g)?;
        //
        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}
#[allow(dead_code)]
pub fn groth_param_gen_s() -> <Groth16<CurveTypeG> as SNARK<Fr>>::ProvingKey {
    
    //type MyMerkleTree=MerkleTree::<MyMerkleTreeParams>;
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

    let circuit= MerkleTreeCircuit{
        leaf_crh_params: (leaf_crh_params.clone()),
        two_to_one_crh_params: (two_to_one_crh_params.clone()),
        root: (root.clone()),
        leaf: (leaf.clone()),
        authentication_path: Some(proof.clone()),
    };
     generate_random_parameters::<CurveTypeG, _, _>(circuit, &mut rng).unwrap()
    }

pub fn groth_proof_gen_s(
    param: &<Groth16<CurveTypeG> as SNARK<Fr>>::ProvingKey,
    circuit: MerkleTreeCircuit,
    seed: &[u8; 32],
) -> <Groth16<CurveTypeG> as SNARK<Fr>>::Proof {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    create_random_proof(circuit, &param, &mut rng).unwrap()
}
    
#[allow(dead_code)]
pub fn groth_verify_s(
    param: &<Groth16<CurveTypeG> as SNARK<Fr>>::ProvingKey,
    proof: &<Groth16<CurveTypeG> as SNARK<Fr>>::Proof,
    output: Root,
) -> bool {
    let pvk = prepare_verifying_key(&param.vk);
	//let output_fq: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(output).unwrap();
    verify_proof(&pvk, &proof, &[output]).unwrap()
}


#[allow(unused)]
#[test]
fn ttest() {
    use ark_relations::r1cs::ConstraintSystem;
    use ark_relations::*;
    let cs = ConstraintSystem::new_ref();

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

    let rootvar = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&root)).unwrap();

    let leafvar = UInt8::new_witness(ark_relations::ns!(cs, "leaf_var"), || Ok(&leaf)).unwrap();

    // Then, we allocate the public parameters as constants:
    let leaf_crh_paramsvar = LeafHashParamsVar::new_constant(cs.clone(), &leaf_crh_params).unwrap();
    let two_to_one_crh_paramsvar =
        TwoToOneHashParamsVar::new_constant(cs.clone(), &two_to_one_crh_params).unwrap();

    // Finally, we allocate our path as a private witness variable:
    let pathvar = SimplePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
        Ok(&proof)
    }).unwrap();

    let leaf_bytes = vec![leafvar; 1];
    let leaf_g :&[_] =leaf_bytes.as_slice();
    // Now, we have to check membership. How do we do that?
    // Hint: look at https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/constraints.rs#L135

    // TODO: FILL IN THE BLANK!
        let is_member = pathvar.verify_membership(
            &leaf_crh_paramsvar, 
            &two_to_one_crh_paramsvar, 
            &rootvar, 
            &leaf_g).unwrap();
    //
    is_member.enforce_equal(&Boolean::TRUE).unwrap();
    // native_sponge.absorb(&absorb1);
    // constraint_sponge.absorb(&absorb1_var).unwrap();

    // let squeeze1 = native_sponge.squeeze_native_field_elements(SIZEOFOUTPUT);
    // let squeeze2 = constraint_sponge.squeeze_field_elements(SIZEOFOUTPUT).unwrap();
    
    // let c =squeeze2.value().unwrap();

    // assert_eq!(c, squeeze1);
     assert!(cs.is_satisfied().unwrap());

}