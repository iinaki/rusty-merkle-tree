use crate::{direction::Direction, merkle_hash::MerkleHash};

/// The `ProofOfInclusion` struct contains the proof of inclusion for a leaf in a Merkle Tree.
pub struct ProofOfInclusion {
    proof: Vec<(MerkleHash, Direction)>,
    leaf: MerkleHash,
}

impl ProofOfInclusion {
    /// Creates a new proof of inclusion from a certain leaf and its path to the root.
    pub fn new_from(leaf: MerkleHash, proof: Vec<(MerkleHash, Direction)>) -> Self {
        ProofOfInclusion { leaf, proof }
    }

    /// Prints the proof of inclusion.
    pub fn print(self) {
        println!("Proof of Inclusion for the leaf: {:?}", &self.leaf);
        for (hash, direction) in self.proof {
            println!("{:?} - {:?}", hash, direction);
        }
    }

    /// Returns an interator over the proof of inclusion.
    pub fn iter(&self) -> impl Iterator<Item = &(MerkleHash, Direction)> {
        self.proof.iter()
    }
}
