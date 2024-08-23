use sha3::{Digest, Sha3_256};

use super::merkle_hash::MerkleHash;

/// A Merkle Tree that 
pub struct MerkleTree {
    levels: Vec<Vec<MerkleHash>>,
}

impl MerkleTree {
    /// Creates a new MerkleTree from a list of hashes.
    pub fn new_from_hashes(hashes: Vec<MerkleHash>) -> MerkleTree {
        let mut tree = MerkleTree { levels: vec![] };
        MerkleTree::build_tree(&mut tree, hashes);
        tree
    }

    pub fn new_from_hasables<T: AsRef<[u8]>>(data: Vec<T>) -> MerkleTree {
        let hashes = data.iter().map(|d| {
            let mut hasher = Sha3_256::new();
            hasher.update(d.as_ref());
            let result = hasher.finalize();
            result.into()
        }).collect();

        MerkleTree::new_from_hashes(hashes)
    }

    fn build_tree(tree: &mut MerkleTree, hashes: Vec<MerkleHash>) {
        tree.levels.push(hashes.clone());

        if hashes.len() == 1 {
            return;
        }

        let mut next_hashes = vec![];
        for i in (0..hashes.len()).step_by(2) {
            let left = hashes[i];
            let right = if i + 1 < hashes.len() {
                hashes[i + 1]
            } else {
                left
            };

            next_hashes.push(MerkleTree::combine_hashes(left, right));
        }

        MerkleTree::build_tree(tree, next_hashes);
    }

    fn combine_hashes(left: MerkleHash, right: MerkleHash) -> MerkleHash {
        left.to_vec().extend_from_slice(&right);

        let mut cobined = left.clone();

        let mut hasher = Sha3_256::new();
        hasher.update(&mut cobined);
        let result = hasher.finalize();
        
        result.into()
    }

    /// Returns the root of the Merkle Tree, which is the Merkle Root.
    pub fn root(&self) -> MerkleHash {
        self.levels[self.levels.len() - 1][0].clone()
    }

    /// Verifies that a given hash is contained in the Merkle Tree
    pub fn verify(&self, leaf: MerkleHash, mut index: u32) -> bool {
        let mut computed_root = leaf;

        for level in self.levels.iter() {
            if level.len() == 1 {
                break;
            }

            if index % 2 == 0 {
                computed_root = MerkleTree::combine_hashes(computed_root, level[(index + 1) as usize]);
            } else {
                computed_root = MerkleTree::combine_hashes(level[(index - 1) as usize], computed_root);
            }

            index /= 2;
        }

        computed_root == self.root()
    }

    // path to the leaf node
    // fn generate_proof
}


#[cfg(test)]
mod test {
    use sha3::{Digest, Sha3_256};

    use crate::merkle_tree::MerkleTree;

    #[test]
    fn build_simple_tree() {
        let data = vec![
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
        ];

        let tree = MerkleTree::new_from_hashes(data);

        println!("LEVEL 1: {:?}", tree.levels[0]);
        println!("LEVEL 2: {:?}", tree.levels[1]);
        println!("LEVEL 3: {:?}", tree.levels[2]);

        let mut hasher = Sha3_256::new();
        hasher.update([1; 32]);
        let result = hasher.finalize();
        
        let hash: [u8; 32] = result.into();
        println!("HASH 1: {:?}", hash);

        assert_eq!(tree.levels.len(), 3);
        assert_eq!(tree.levels[0].len(), 4);
        assert_eq!(tree.levels[1].len(), 2);
        assert_eq!(tree.levels[2].len(), 1);
    }

    #[test]
    fn build_simple_tree_from_strings() {
        let data = vec![
            "q onda",
            "q tal",
            "q pex",
            "qqqqq",
        ];

        let tree = MerkleTree::new_from_hasables(data);

        println!("LEVEL 1: {:?}", tree.levels[0]);
        println!("LEVEL 2: {:?}", tree.levels[1]);
        println!("LEVEL 3: {:?}", tree.levels[2]);

        assert_eq!(tree.levels.len(), 3);
        assert_eq!(tree.levels[0].len(), 4);
        assert_eq!(tree.levels[1].len(), 2);
        assert_eq!(tree.levels[2].len(), 1);
    }

    #[test]
    fn verify_inclusion_in_simple_tree_from_strings() {
        let data = vec![
            "q onda",
            "q tal",
            "q pex",
            "qqqqq",
        ];

        let tree = MerkleTree::new_from_hasables(data);

        let mut hasher = Sha3_256::new();
        hasher.update("q pex");
        let result = hasher.finalize();
        
        let hash: [u8; 32] = result.into();

        assert!(tree.verify(hash, 2));
    }

    #[test]
    fn verify_inclusion_in_big_tree_from_strings() {
        let data = vec![
            "q onda0",
            "q onda1",
            "q onda2",
            "q onda3",
            "q onda4",
            "q onda5",
            "q onda6",
            "q onda7",
            "q onda8",
            "q onda9",
            "q onda10",
            "q onda11",
            "q onda12",
            "q onda13",
            "q onda14",
            "q onda15",
            "q onda16",
            "q onda17",
            "q onda18",
            "q onda19",
            "q onda20",
            "q onda21",
            "q onda22",
            "q onda23",
            "q onda24",
            "q onda25",
            "q onda26",
            "q onda27",
            "q onda28",
            "q onda29",
            "q onda30",
            "q onda31",
        ];

        let tree = MerkleTree::new_from_hasables(data);

        let mut hasher = Sha3_256::new();
        hasher.update("q onda17");
        let result = hasher.finalize();
        
        let hash: [u8; 32] = result.into();

        assert!(tree.verify(hash, 17));
    }
}
