use crate::{direction::Direction, merkle_hash::MerkleHash};

pub struct ProofOfInclusion {
    proof: Vec<(MerkleHash, Direction)>,
    leaf: MerkleHash,
}

impl ProofOfInclusion {
    pub fn new_from(leaf: MerkleHash, proof: Vec<(MerkleHash, Direction)>) -> Self {
        ProofOfInclusion { leaf, proof }
    }

    pub fn print(self) {
        println!("Proof of Inclusion for the leaf: {:?}", &self.leaf);
        for (hash, direction) in self.proof {
            println!("{:?} - {:?}", hash, direction);
        }
    }
}
