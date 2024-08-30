use clap::{Parser, Subcommand};

use crate::merkle_tree::MerkleTree;
use std::error::Error;
use std::vec;

#[derive(Parser, Debug)]
#[command(name = "tree")]
struct Args {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Creates a new Merkle Tree from a file with elements.
    /// If the `--hash` flag is present, the elements are hashed before being added to the tree.
    Create {
        /// Path to the file containing the elements
        path: String,

        /// Hash the elements before adding to the tree
        #[arg(long)]
        hash: bool,
    },

    /// Shows the current state of the Merkle Tree.
    Show,

    /// Verifies if an element is included in the Merkle Tree.
    Verify {
        /// The element to verify
        elem: String,

        /// Optionally provide the index for verification
        index: Option<u32>,
    },

    /// Shows the proof of inclusion for an element.
    Proof {
        /// The element to get proof of inclusion for
        elem: String,

        /// Optionally provide the index for proof of inclusion
        index: Option<u32>,
    },

    /// Adds an element to the Merkle Tree.
    /// If the `--hash` flag is present, the element is hashed before being added to the tree.
    Add {
        /// The element to add
        elem: String,

        /// Hash the element before adding to the tree
        #[arg(long)]
        hash: bool,
    },

    /// Exit the CLI
    Exit,
}

/// The `CLI` struct is used to manage the command line interface of the Merkle Tree.
pub struct CLI {
    tree: MerkleTree,
}

/// Implementation of the `Default` trait for the `CLI` struct.
impl Default for CLI {
    fn default() -> Self {
        Self::new()
    }
}

impl CLI {
    /// Creates a new `CLI` struct.
    pub fn new() -> Self {
        CLI {
            tree: MerkleTree::new_from_hashables(vec![""]),
        }
    }

    pub fn new_from_tree(tree: MerkleTree) -> Self {
        CLI { tree }
    }

    /// Processes the input commands from the user and manages the CLI.
    fn manage_input(&mut self, commands: Vec<String>, running: &mut bool) {
        match Args::try_parse_from(commands.iter()) {
            Ok(cli) => match cli.cmd {
                Commands::Create { path, hash } => self.handle_create_tree(path, hash),
                Commands::Show => self.tree.print(),
                Commands::Verify { elem, index } => self.handle_verify_inclusion(elem, index),
                Commands::Proof { elem, index } => self.handle_proof_of_inclusion(elem, index),
                Commands::Add { elem, hash } => self.handle_add_element(elem, hash),
                Commands::Exit => {
                    println!("Exiting...");
                    *running = false;
                }
            },
            Err(e) => {
                println!("{}", e);
            }
        }
    }

    /// Processes the file with the elements to be added to the Merkle Tree.
    pub fn process_file(path: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let elements = std::fs::read_to_string(path)?;

        let elements = elements
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect();

        Ok(elements)
    }

    /// Handles the creation of a new Merkle Tree.
    /// The tree can be created from a file with elements or from a file with hashes. The `--hash` flag is used to hash the elements before adding them to the tree.
    fn handle_create_tree(&mut self, path: String, hash: bool) {
        let elements = match CLI::process_file(&path) {
            Ok(elements) => elements,
            Err(e) => {
                println!("Failed to read file: {}", e);
                return;
            }
        };

        if hash {
            self.tree = MerkleTree::new_from_hashables(elements);
        } else {
            self.tree = MerkleTree::new_from_hashes(elements);
        }

        println!(
            "Merkle Tree created from file: {:?}, use 'tree show' to view te current tree.",
            path
        );
    }

    /// Handles the verification of the inclusion of an element in the Merkle Tree.
    fn handle_verify_inclusion(&mut self, elem: String, index: Option<u32>) {
        if let Some(index) = index {
            if self.tree.verify_with_index(elem.clone(), index) {
                println!("{:?} is included in the tree at index {}. Run the `proof` command to see its Proof of Inclusion", elem, index);
            } else {
                println!("{:?} is not included in the tree at index {}.", elem, index);
            }
        } else if self.tree.verify(elem.clone()) {
            println!("{:?} is included in the tree. Run the `proof` command to see its Proof of Inclusion.", elem);
        } else {
            println!("{:?} is not included in the tree.", elem);
        }
    }

    /// Handles the generation of the proof of inclusion of an element in the Merkle Tree.
    fn handle_proof_of_inclusion(&mut self, elem: String, index: Option<u32>) {
        if let Some(index) = index {
            match self.tree.proof_of_inclusion_with_index(elem.clone(), index) {
                Ok(proof) => {
                    proof.print();
                }
                Err(_) => {
                    println!("{:?} is not included in the tree at index {}.", elem, index);
                }
            }
        } else {
            match self.tree.proof_of_inclusion(elem.clone()) {
                Ok(proof) => {
                    proof.print();
                }
                Err(_) => {
                    println!("{:?} is not included in the tree.", elem);
                }
            }
        }
    }

    /// Handles the addition of an element to the Merkle Tree.
    /// The element can be added as a hash or as a string. The `--hash` flag is used to hash the element before adding it to the tree.
    fn handle_add_element(&mut self, elem: String, hash: bool) {
        if hash {
            match self.tree.add_data(elem.clone()) {
                Ok(_) => (),
                Err(_) => {
                    println!("{} is already in the tree!", elem);
                    return;
                }
            }
        } else {
            match self.tree.add_hash(elem.clone()) {
                Ok(_) => (),
                Err(_) => {
                    println!("{} is already in the tree!", elem);
                    return;
                }
            }
        }

        println!("{:?} added to the tree.", elem);
    }

    /// Reads the input from the user and returns a vector with the commands.
    fn get_commands(input: &mut String) -> Vec<String> {
        match std::io::stdin().read_line(input) {
            Ok(_) => (),
            Err(e) => println!("Failed to read line: {}", e),
        };

        let line = input.trim();
        match shlex::split(line).ok_or("error: Invalid quoting") {
            Ok(args) => args,
            Err(e) => {
                println!("{}", e);
                vec![]
            }
        }
    }

    /// Runs the CLI.
    pub fn run(&mut self) {
        println!("Welcome to the Merkle Tree CLI, type 'tree help' to see the list of commands.");

        let mut input = "".to_string();
        let mut running = true;

        while running {
            let args = CLI::get_commands(&mut input);

            self.manage_input(args, &mut running);

            input.clear();
        }
    }
}
