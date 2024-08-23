pub struct MerkleTree {
    pub tree: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new_from_hashes(hashes: Vec<[u8; 32]>) -> MerkleTree {
        let leafs = hashes;
    }

}
