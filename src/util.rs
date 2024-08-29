use crate::{cli::CLI, merkle_tree::MerkleTree};

/// Runs an example from a file.
pub fn run_example_from_path(path: &str) {
    let elements = match CLI::process_file(path) {
        Ok(elements) => elements,
        Err(e) => {
            println!("Failed to read file: {}", e);
            return;
        }
    };

    let tree = MerkleTree::new_from_hashes(elements);

    let mut cli = CLI::new_from_tree(tree);
    println!(
        "In this example the Merkle Tree is created from file: {:?}, use 'show' to view te current tree.",
        path
    );
    cli.run();
}
