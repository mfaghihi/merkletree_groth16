# Example for ZKP of Merkle tree using Groth16

This repo contains an example of building zero-knowlege prover-verifier instances using Arkworks' zkSNARK implementation for: 

*  Merkle tree membership proof when both the leaf and the path are private inputs 

To choose one of the curves (Bls12-377, Bls12-381, Bn_254), change the default ```[features]``` in the Cargo.toml file in each example; 

To change the size of input, change the value of ```SIZEOFINPUT``` in lib.rs.

