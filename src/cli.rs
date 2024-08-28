use crate::merkle_tree::MerkleTree;
use std::error::Error;
use std::{io, vec};

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
            tree: MerkleTree::new_from_hasables(vec![""]),
        }
    }

    pub fn new_from_tree(tree: MerkleTree) -> Self {
        CLI { tree }
    }

    /// Processes the input commands from the user and manages the CLI.
    fn manage_input(&mut self, commands: Vec<&str>, running: &mut bool) {
        match commands[0] {
            "exit" => {
                println!("Exiting...");
                *running = false;
            }
            "help" => {
                CLI::print_help();
            }
            "create" => {
                self.handle_create_tree(commands);
            }
            "show" => {
                self.tree.print();
            }
            "verify" => {
                self.handle_verify_inclusion(commands);
            }
            "proof" => {
                self.handle_proof_of_inclusion(commands);
            }
            "add" => {
                self.handle_add_element(commands);
            }
            _ => {
                println!("Invalid command. Type 'help' to see the list of commands.");
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

        let elements: Vec<&str> = elements.split("\n").collect();

        Ok(elements
            .iter()
            .map(|element| element.trim().to_string())
            .collect())
    }

    /// Handles the creation of a new Merkle Tree.
    /// The tree can be created from a file with elements or from a file with hashes. The `-h` flag is used to hash the elements before adding them to the tree.
    fn handle_create_tree(&mut self, commands: Vec<&str>) {
        if commands.len() < 2 || commands.len() > 3 {
            println!("Invalid number of arguments. Usage: create <path/to/elements.txt>");
            return;
        }

        let path = commands[1];

        let elements = match CLI::process_file(path) {
            Ok(elements) => elements,
            Err(e) => {
                println!("Failed to read file: {}", e);
                return;
            }
        };

        if commands.len() == 3 && commands[2] == "-h" {
            self.tree = MerkleTree::new_from_hasables(elements);
        } else {
            self.tree = MerkleTree::new_from_hashes(elements);
        }

        println!(
            "Merkle Tree created from file: {:?}, use 'show' to view te current tree.",
            path
        );
    }

    /// Handles the verification of the inclusion of an element in the Merkle Tree.
    fn handle_verify_inclusion(&mut self, commands: Vec<&str>) {
        if commands.len() != 2 {
            println!("Invalid number of arguments. Usage: verify <element>");
            return;
        }

        let element = commands[1];

        if self.tree.verify(element.to_string()) {
            println!("{:?} is included in the tree.", element);
        } else {
            println!("{:?} is not included in the tree.", element);
        }
    }

    /// Handles the generation of the proof of inclusion of an element in the Merkle Tree.
    fn handle_proof_of_inclusion(&mut self, commands: Vec<&str>) {
        if commands.len() != 2 {
            println!("Invalid number of arguments. Usage: proof <element>");
            return;
        }

        let element = commands[1];

        match self.tree.proof_of_inclusion(element.to_string()) {
            Ok(proof) => {
                proof.print();
            }
            Err(_) => {
                println!("{:?} is not included in the tree.", element);
            }
        }
    }

    /// Handles the addition of an element to the Merkle Tree.
    /// The element can be added as a hash or as a string. The `-h` flag is used to hash the element before adding it to the tree.
    fn handle_add_element(&mut self, commands: Vec<&str>) {
        if commands.len() < 2 || commands.len() > 3 {
            println!("Invalid number of arguments. Usage: add <element>");
            return;
        }

        let element = commands[1];

        if commands.len() == 3 && commands[2] == "-h" {
            match self.tree.add_data(element) {
                Ok(_) => (),
                Err(_) => {
                    println!("{} is already in the tree!", element);
                    return;
                }
            }
        } else {
            match self.tree.add_hash(element.to_string()) {
                Ok(_) => (),
                Err(_) => {
                    println!("{} is already in the tree!", element);
                    return;
                }
            }
        }

        println!("{:?} added to the tree.", element);
    }

    /// Reads the input from the user and returns a vector with the commands.
    fn get_commands(input: &mut String) -> Vec<&str> {
        match io::stdin().read_line(input) {
            Ok(_) => (),
            Err(e) => println!("Failed to read line: {}", e),
        };

        *input = input.trim().to_string();
        input.split(&" ").collect()
    }

    /// Runs the CLI.
    pub fn run(&mut self) {
        println!("Welcome to the Merkle Tree CLI, type 'help' to see the list of commands.");

        let mut input = "".to_string();
        let mut running = true;

        while running {
            let commands = CLI::get_commands(&mut input);

            self.manage_input(commands, &mut running);

            input.clear();
        }
    }
}
