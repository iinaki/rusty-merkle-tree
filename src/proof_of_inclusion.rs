use crate::{direction::Direction, merkle_hash::MerkleHash};

pub struct ProofOfInclusion {
    proof: Vec<(MerkleHash, Direction)>,
    leaf: MerkleHash,
}

impl ProofOfInclusion {
    pub fn new_from(leaf: MerkleHash, proof: Vec<(MerkleHash, Direction)>) -> Self {
        ProofOfInclusion { leaf, proof }
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        let hex_chars: Vec<String> = bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
        hex_chars.join("")
    }

    pub fn print(self) {
        println!(
            "Proof of Inclusion for the leaf: {:?}",
            ProofOfInclusion::bytes_to_hex(&self.leaf)
        );
        for (hash, direction) in self.proof {
            println!(
                "{:?} - {:?}",
                ProofOfInclusion::bytes_to_hex(&hash),
                direction
            );
        }
    }
}
