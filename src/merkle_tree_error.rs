/// Enum representing possible errors that can occur while running the tree.
#[derive(Debug)]
pub enum MerkleTreeError {
    /// Failed to build the Merkle Tree.
    FailedToBuild(String),
    /// The hash is not part of the tree.
    InvalidHash(String),
    /// The hash already exists in the tree.
    HashAlreadyExists(String),
    /// Failed to process the elements file.
    FailedToProcessFile(String),
}
