use crate::{direction::Direction, merkle_hash::MerkleHash};

pub type ProofOfInclusion = Vec<(MerkleHash, Direction)>;
