use clap::{Parser, Subcommand};

use crate::merkle_tree::MerkleTree;
use std::error::Error;
use std::vec;

#[derive(Parser)]
#[command(disable_help_flag = true)]
#[command(disable_help_subcommand = true)]
struct Args {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Create {
        path: String,
        #[arg(long)]
        hash: bool,
    },
    Show,
    Help,
    Verify {
        elem: String,
        index: Option<u32>,
    },
    Proof {
        elem: String,
        index: Option<u32>,
    },
    Add {
        elem: String,
        #[arg(long)]
        hash: bool,
    },
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
        match Args::try_parse_from(commands.iter()).map_err(|e| e.to_string()) {
            Ok(cli) => match cli.cmd {
                Commands::Create { path, hash } => self.handle_create_tree(path, hash),
                Commands::Show => self.tree.print(),
                Commands::Help => CLI::print_help(),
                Commands::Verify { elem, index } => self.handle_verify_inclusion(elem, index),
                Commands::Proof { elem, index } => self.handle_proof_of_inclusion(elem, index),
                Commands::Add { elem, hash } => self.handle_add_element(elem, hash),
                Commands::Exit => {
                    println!("Exiting...");
                    *running = false;
                }
            },
            Err(_) => {
                println!("That's not a valid command - use the help command if you are stuck.")
            }
        }
    }

    /// Prints the list of commands available in the CLI.
    fn print_help() {
        println!("COMMANDS \n");
        println!("-- CREATE --");
        println!("create <path/to/elements.txt> <-h>");
        println!("- Creates a new Merkle Tree from a file with elements. If the -h flag is present, the elements are hashed before being added to the tree. \n");
        println!("-- SHOW --");
        println!("show");
        println!("- Shows the current state of the Merkle Tree. \n");
        println!("-- VERIFY --");
        println!("verify <element>");
        println!("- Verifies if an element is included in the tree. \n");
        println!("-- PROOF --");
        println!("proof <element>");
        println!("- Shows the proof of inclusion for an element. \n");
        println!("-- ADD --");
        println!("add <element> <-h>");
        println!("- Adds an element to the tree. If the -h flag is present, the element is hashed before being added to the tree. \n");
        println!("-- EXIT --");
        println!("exit");
        println!("- Exits the program.")
    }

    /// Processes the file with the elements to be added to the Merkle Tree.
    pub fn process_file(path: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let elements = std::fs::read_to_string(path)?;

        let elements = elements
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
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
            "Merkle Tree created from file: {:?}, use 'show' to view te current tree.",
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
        let mut args = match shlex::split(line).ok_or("error: Invalid quoting") {
            Ok(args) => args,
            Err(e) => {
                println!("{}", e);
                return vec![];
            }
        };

        args.insert(0, "app".to_string());

        args
    }

    /// Runs the CLI.
    pub fn run(&mut self) {
        println!("Welcome to the Merkle Tree CLI, type 'help' to see the list of commands.");

        let mut input = "".to_string();
        let mut running = true;

        while running {
            let args = CLI::get_commands(&mut input);

            self.manage_input(args, &mut running);

            input.clear();
        }
    }
}
