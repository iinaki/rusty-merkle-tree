use sha3::{Digest, Sha3_256};

use crate::direction::Direction;
use crate::merkle_tree_error::MerkleTreeError;
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
#[derive(Debug)]
pub struct MerkleTree {
    levels: Vec<Vec<MerkleHash>>,
}

impl MerkleTree {
    /// Creates a new MerkleTree from a list of hashes.
    pub fn new_from_hashes(hashes: Vec<MerkleHash>) -> Result<MerkleTree, MerkleTreeError> {
        let mut tree = MerkleTree { levels: vec![] };
        MerkleTree::build_tree(&mut tree, hashes)?;
        Ok(tree)
    }

    /// Creates a new MerkleTree from a list of objects that can be converted to byte slices (== that are hashable).
    pub fn new_from_hashables(data: Vec<impl AsRef<[u8]>>) -> Result<MerkleTree, MerkleTreeError> {
        let hashes = data
            .iter()
            .map(|d| {
                let mut hasher = Sha3_256::new();
                hasher.update(d);
                let result = hasher.finalize();
                MerkleTree::bytes_to_hex(&result)
            })
            .collect();

        MerkleTree::new_from_hashes(hashes)
    }

    /// Recursive function that builds the Merkle Tree from a list of hashes.
    fn build_tree(
        tree: &mut MerkleTree,
        mut hashes: Vec<MerkleHash>,
    ) -> Result<(), MerkleTreeError> {
        if hashes.len() == 1 {
            tree.levels.push(hashes);
            return Ok(());
        }

        if hashes.len() % 2 != 0 {
            let last = match hashes.last() {
                Some(last) => last.clone(),
                None => {
                    return Err(MerkleTreeError::FailedToBuild(
                        "No last element in hashes".to_string(),
                    ));
                }
            };
            hashes.push(last);
        }

        let len = hashes.len();
        tree.levels.push(hashes.clone());

        let mut next_hashes = vec![];
        for i in (0..len).step_by(2) {
            let left = &hashes[i];
            let right = &hashes[i + 1];

            next_hashes.push(MerkleTree::combine_hashes(left, right));
        }

        MerkleTree::build_tree(tree, next_hashes)
    }

    /// Concatenates two hashes and returns the hash of the concatenation.
    // fn combine_hashes(mut left: MerkleHash, right: &MerkleHash) -> MerkleHash {
    //     left = left + right;

    //     let mut hasher = Sha3_256::new();
    //     hasher.update(left);
    //     let result = hasher.finalize();

    //     MerkleTree::bytes_to_hex(&result)
    // }
    fn combine_hashes(left: &MerkleHash, right: &MerkleHash) -> MerkleHash {
        let mut combined = left.clone();
        combined.push_str(right);

        let mut hasher = Sha3_256::new();
        hasher.update(combined);
        let result = hasher.finalize();

        MerkleTree::bytes_to_hex(&result)
    }

    /// Returns the root of the Merkle Tree, which is the Merkle Root.
    fn root(&self) -> &MerkleHash {
        &self.levels[self.levels.len() - 1][0]
    }

    /// Verifies that a given hash is contained in the Merkle Tree, in O(log n) time, with n = number of leaf hashes.
    ///
    /// # Parameters
    /// - `leaf`: The hash to verify
    /// - `index`: The index of the hash in the bottom level of the tree
    pub fn verify_with_index(&self, leaf: &MerkleHash, index: u32) -> bool {
        if self.levels[0][index as usize] != *leaf {
            return false;
        }

        let proof = match self.proof_of_inclusion_with_index(leaf, index) {
            Ok(proof) => proof,
            Err(_) => return false,
        };

        let mut computed_root = leaf.clone();

        for (hash, direction) in proof.iter() {
            computed_root = match direction {
                Direction::Left => MerkleTree::combine_hashes(hash, &computed_root),
                Direction::Right => MerkleTree::combine_hashes(&computed_root, hash),
            };
        }

        &computed_root == self.root()
    }

    /// Verifies that a given hash is contained in the Merkle Tree, in O(n) time, with n = number of leaf hashes.
    ///
    /// # Parameters
    /// - `leaf`: The hash to verify
    pub fn verify(&self, leaf: &MerkleHash) -> bool {
        let hash_index = match self.levels[0].iter().position(|h| h == leaf) {
            Some(index) => index,
            None => return false,
        };

        self.verify_with_index(leaf, hash_index as u32)
    }

    /// Returns the hash of the given data
    ///
    /// # Parameters
    /// - `data`: An object that can be converted to a byte slice
    pub fn get_hash_of(data: &impl AsRef<[u8]>) -> MerkleHash {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        MerkleTree::bytes_to_hex(&result)
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
        leaf: &MerkleHash,
        mut index: u32,
    ) -> Result<ProofOfInclusion, MerkleTreeError> {
        if self.levels[0][index as usize] != *leaf {
            return Err(MerkleTreeError::InvalidHash(
                "Hash is not part of the tree".to_string(),
            ));
        }

        let mut proof = vec![];

        for level in self.levels.iter() {
            if level.len() == 1 {
                break;
            }

            if index % 2 == 0 {
                if index + 1 < level.len() as u32 {
                    proof.push((level[(index + 1) as usize].clone(), Direction::Right));
                } else {
                    proof.push((level[index as usize].clone(), Direction::Right));
                }
            } else {
                proof.push((level[(index - 1) as usize].clone(), Direction::Left));
            }

            index /= 2;
        }

        Ok(ProofOfInclusion::new_from(leaf.clone(), proof))
    }

    /// Returns a proof of inclusion for a given hash in the Merkle Tree. The proof generated conains the hashes of the siblings of the nodes in the path from the leaf to the root, and their directions. In O(n) time, with n = number of leaf hashes.
    ///
    /// # Parameters
    /// - `leaf`: The hash to generate the proof for
    ///
    /// # Returns
    /// A Result that, if the hash given is included in the tree, contains a `ProofOfInclusion` containing the proof of inclusion for the given hash. If the hash is not included in the tree, an error message is returned.
    pub fn proof_of_inclusion(
        &self,
        leaf: &MerkleHash,
    ) -> Result<ProofOfInclusion, MerkleTreeError> {
        let hash_index = match self.levels[0].iter().position(|h| h == leaf) {
            Some(index) => index,
            None => {
                return Err(MerkleTreeError::InvalidHash(
                    "Hash is not part of the tree".to_string(),
                ))
            }
        };

        self.proof_of_inclusion_with_index(leaf, hash_index as u32)
    }

    /// Adds a hash to the Merkle Tree, updating the tree structure.
    ///
    /// # Parameters
    /// - `hash`: The hash to add to the tree
    pub fn add_hash(&mut self, hash: MerkleHash) -> Result<(), MerkleTreeError> {
        let len = self.levels[0].len();

        if self.verify(&hash) {
            return Err(MerkleTreeError::HashAlreadyExists(
                "Hash is already contained in the tree".to_string(),
            ));
        }

        if len >= 2 && self.levels[0][len - 1] == self.levels[0][len - 2] {
            self.levels[0][len - 1] = hash;
        } else {
            self.levels[0].push(hash);
        }

        let mut new_tree = MerkleTree { levels: vec![] };

        MerkleTree::build_tree(&mut new_tree, self.levels[0].clone())?;

        self.levels = new_tree.levels;
        Ok(())
    }

    /// Adds an element that will be hashed before adding it to the Merkle Tree, .
    pub fn add_data(&mut self, data: impl AsRef<[u8]>) -> Result<(), MerkleTreeError> {
        let hash = MerkleTree::get_hash_of(&data);
        self.add_hash(hash)
    }

    /// Converts a byte slice to a hexadecimal string.
    fn bytes_to_hex(bytes: &[u8]) -> String {
        let hex_chars: Vec<String> = bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
        hex_chars.join("")
    }

    /// Prints the Merkle Tree structure.
    pub fn print(&self) {
        for i in (0..self.levels.len()).rev() {
            println!("LEVEL {}:", self.levels.len() - i - 1);
            for hash in self.levels[i].iter() {
                println!("- {:?}", hash);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use sha3::{Digest, Sha3_256};

    use crate::merkle_tree::MerkleTree;

    #[test]
    fn build_simple_tree() {
        let data = vec![[1; 32], [2; 32], [3; 32], [4; 32]];

        let tree = MerkleTree::new_from_hashables(data).unwrap();

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

        let tree = MerkleTree::new_from_hashables(data).unwrap();

        tree.print();

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

        let tree = MerkleTree::new_from_hashables(data).unwrap();

        let hash = MerkleTree::get_hash_of(&"something04");
        println!("HASH: {:?}", hash);

        assert!(tree.verify_with_index(&hash, 4));
        tree.print()
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

        let tree = MerkleTree::new_from_hashables(data).unwrap();

        let hash = MerkleTree::get_hash_of(&"something017");

        assert!(tree.verify_with_index(&hash, 17));

        tree.print()
    }

    #[test]
    fn proof_of_inclusion_in_big_tree_from_strings() {
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

        let tree = MerkleTree::new_from_hashables(data).unwrap();

        let hash = MerkleTree::get_hash_of(&"something017");

        let proof = tree.proof_of_inclusion(&hash).unwrap();

        proof.print();
    }

    #[test]
    #[should_panic]
    fn proof_of_inclusion_fails() {
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

        let tree = MerkleTree::new_from_hashables(data).unwrap();

        let hash = MerkleTree::get_hash_of(&"not in the tree");

        let _proof = tree.proof_of_inclusion(&hash).unwrap();
    }

    #[test]
    fn add_to_tree() {
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
        ];

        let mut tree = MerkleTree::new_from_hashables(data).unwrap();
        println!("TREE BEFORE ADDING:");
        tree.print();

        let new_data = MerkleTree::get_hash_of(&"something099");
        let _ = tree.add_hash(new_data.clone());

        assert!(tree.verify(&new_data));

        let proof = tree.proof_of_inclusion(&new_data).unwrap();
        println!("PROOF OF ADDED:");
        proof.print();

        println!("TREE AFTER ADDING:");
        tree.print()
    }
}
