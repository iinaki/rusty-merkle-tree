use sha3::{Digest, Sha3_256};

use crate::direction::Direction;
use crate::proof_of_inclusion::ProofOfInclusion;

use super::merkle_hash::MerkleHash;

/// A Merkle Tree implementation
///
/// # Methods
/// - `new_from_hashes`: Creates a new MerkleTree from a list of hashes.
/// - `new_from_hasables`: Creates a new MerkleTree from a list of objects that are hashable.
/// - `root`: Returns the root of the Merkle Tree, which is the Merkle Root.
/// - `verify`: Verifies that a given hash is contained in the Merkle Tree.
/// - `proof_of_inclusion`: Returns a proof of inclusion for a given hash in the Merkle Tree.
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

    /// Creates a new MerkleTree from a list of objects that can be converted to byte slices (== that are hashable).
    pub fn new_from_hasables(data: Vec<impl AsRef<[u8]>>) -> MerkleTree {
        let hashes = data
            .iter()
            .map(|d| {
                let mut hasher = Sha3_256::new();
                hasher.update(d);
                let result = hasher.finalize();
                result.into()
            })
            .collect();

        MerkleTree::new_from_hashes(hashes)
    }

    /// Recursive function that builds the Merkle Tree from a list of hashes.
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

    /// Concatenates two hashes and returns the hash of the concatenation.
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

    /// Verifies that a given hash is contained in the Merkle Tree, in O(log n) time, with n = number of leaf hashes.
    ///
    /// # Parameters
    /// - `leaf`: The hash to verify
    /// - `index`: The index of the hash in the bottom level of the tree
    pub fn verify_with_index(&self, leaf: MerkleHash, mut index: u32) -> bool {
        if self.levels[0][index as usize] != leaf {
            return false;
        }

        let mut computed_root = leaf;

        for level in self.levels.iter() {
            if level.len() == 1 {
                break;
            }

            if index % 2 == 0 {
                computed_root = if index + 1 < level.len() as u32 {
                    MerkleTree::combine_hashes(computed_root, level[(index + 1) as usize])
                } else {
                    MerkleTree::combine_hashes(computed_root, computed_root)
                }
            } else {
                computed_root =
                    MerkleTree::combine_hashes(level[(index - 1) as usize], computed_root);
            }

            index /= 2;
        }

        computed_root == self.root()
    }

    /// Verifies that a given hash is contained in the Merkle Tree, in O(n) time, with n = number of leaf hashes.
    ///
    /// # Parameters
    /// - `leaf`: The hash to verify
    pub fn verify(&self, leaf: MerkleHash) -> bool {
        let hash_index = match self.levels[0].iter().position(|h| h == &leaf) {
            Some(index) => index,
            None => return false,
        };

        self.verify_with_index(leaf, hash_index as u32)
    }

    /// Returns the hash of the given data
    ///
    /// # Parameters
    /// - `data`: An object that can be converted to a byte slice
    pub fn get_hash_of(&self, data: &impl AsRef<[u8]>) -> MerkleHash {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    /// Returns a proof of inclusion for a given hash in the Merkle Tree. The proof generated conains the hashes of the siblings of the nodes in the path from the leaf to the root, and their directions. In O(log n) time, with n = number of leaf hashes..
    ///
    /// # Parameters
    /// - `leaf`: The hash to generate the proof for
    /// - `index`: The index of the hash in the bottom level of the tree
    ///
    /// # Returns
    /// A Result that, if the hash given is included in the tree, contains a `ProofOfInclusion` containing the proof of inclusion for the given hash. If the hash is not included in the tree, an error message is returned.
    pub fn proof_of_inclusion_with_index(
        &self,
        leaf: MerkleHash,
        mut index: u32,
    ) -> Result<ProofOfInclusion, String> {
        if self.levels[0][index as usize] != leaf {
            return Err("Hash not found in tree".to_string());
        }

        let mut computed_root = leaf;
        let mut proof = vec![];

        for level in self.levels.iter() {
            if level.len() == 1 {
                break;
            }

            if index % 2 == 0 {
                computed_root = if index + 1 < level.len() as u32 {
                    proof.push((level[(index + 1) as usize], Direction::Right));
                    MerkleTree::combine_hashes(computed_root, level[(index + 1) as usize])
                } else {
                    proof.push((computed_root, Direction::Right));
                    MerkleTree::combine_hashes(computed_root, computed_root)
                }
            } else {
                computed_root =
                    MerkleTree::combine_hashes(level[(index - 1) as usize], computed_root);
                proof.push((level[(index - 1) as usize], Direction::Left));
            }

            index /= 2;
        }

        Ok(ProofOfInclusion::new_from(leaf, proof))
    }

    /// Returns a proof of inclusion for a given hash in the Merkle Tree. The proof generated conains the hashes of the siblings of the nodes in the path from the leaf to the root, and their directions. In O(n) time, with n = number of leaf hashes.
    ///
    /// # Parameters
    /// - `leaf`: The hash to generate the proof for
    ///
    /// # Returns
    /// A Result that, if the hash given is included in the tree, contains a `ProofOfInclusion` containing the proof of inclusion for the given hash. If the hash is not included in the tree, an error message is returned.
    pub fn proof_of_inclusion(&self, leaf: MerkleHash) -> Result<ProofOfInclusion, String> {
        let hash_index = match self.levels[0].iter().position(|h| h == &leaf) {
            Some(index) => index,
            None => return Err("Hash not found in tree".to_string()),
        };

        self.proof_of_inclusion_with_index(leaf, hash_index as u32)
    }
}

#[cfg(test)]
mod test {
    use sha3::{Digest, Sha3_256};

    use crate::merkle_tree::MerkleTree;

    #[test]
    fn build_simple_tree() {
        let data = vec![[1; 32], [2; 32], [3; 32], [4; 32]];

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
        let data = vec!["something00", "something01", "something02", "something03"];

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
            "something00",
            "something01",
            "something02",
            "something03",
            "something04",
        ];

        let tree = MerkleTree::new_from_hasables(data);

        let mut hasher = Sha3_256::new();
        hasher.update("something04");
        let result = hasher.finalize();

        let hash: [u8; 32] = result.into();
        println!("HASH: {:?}", hash);

        assert!(tree.verify_with_index(hash, 4));
    }

    #[test]
    fn verify_inclusion_in_big_tree_from_strings() {
        let data = vec![
            "something00",
            "something01",
            "something02",
            "something03",
            "something04",
            "something05",
            "something06",
            "something07",
            "something08",
            "something09",
            "something010",
            "something011",
            "something012",
            "something013",
            "something014",
            "something015",
            "something016",
            "something017",
            "something018",
            "something019",
            "something020",
            "something021",
            "something022",
            "something023",
            "something024",
            "something025",
            "something026",
            "something027",
            "something028",
            "something029",
            "something030",
            "something031",
        ];

        let tree = MerkleTree::new_from_hasables(data);

        let mut hasher = Sha3_256::new();
        hasher.update("something017");
        let result = hasher.finalize();

        let hash: [u8; 32] = result.into();

        assert!(tree.verify_with_index(hash, 17));
    }

    #[test]
    fn verify_proof_of_inclusion_in_big_tree_from_strings() {
        let data = vec![
            "something00",
            "something01",
            "something02",
            "something03",
            "something04",
            "something05",
            "something06",
            "something07",
            "something08",
            "something09",
            "something010",
            "something011",
            "something012",
            "something013",
            "something014",
            "something015",
            "something016",
            "something017",
            "something018",
            "something019",
            "something020",
            "something021",
            "something022",
            "something023",
            "something024",
            "something025",
            "something026",
            "something027",
            "something028",
            "something029",
            "something030",
            "something031",
        ];

        let tree = MerkleTree::new_from_hasables(data);

        let hash = tree.get_hash_of(&"something017");

        let proof = tree.proof_of_inclusion(hash).unwrap();

        proof.print();
    }
}
