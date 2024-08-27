use crate::merkle_tree::MerkleTree;
use std::error::Error;
use std::{io, vec};

pub struct CLI {
    tree: MerkleTree,
}

impl CLI {
    pub fn new() -> Self {
        CLI {
            tree: MerkleTree::new_from_hasables(vec![""]),
        }
    }

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

    fn print_help() {
        println!("COMMANDS");
        println!("-- CREATE --");
        println!("create <path/to/elements.txt> <-h>");
        println!("- Creates a new Merkle Tree from a file with elements. If the -h flag is present, the elements are hashed before being added to the tree.");
        println!("");
        println!("-- SHOW --");
        println!("show");
        println!("- Shows the current state of the Merkle Tree.");
        println!("");
        println!("-- VERIFY --");
        println!("verify <element>");
        println!("- Verifies if an element is included in the tree.");
        println!("");
        println!("-- PROOF --");
        println!("proof <element>");
        println!("- Shows the proof of inclusion for an element.");
        println!("");
        println!("-- ADD --");
        println!("add <element> <-h>");
        println!("- Adds an element to the tree. If the -h flag is present, the element is hashed before being added to the tree.");
        println!("");
        println!("-- EXIT --");
        println!("exit");
        println!("- Exits the program.")
    }

    fn process_file(path: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let elements = std::fs::read_to_string(path)?;

        let elements: Vec<&str> = elements.split("\n").collect();

        Ok(elements
            .iter()
            .map(|element| element.trim().to_string())
            .collect())
    }

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

    fn handle_add_element(&mut self, commands: Vec<&str>) {
        if commands.len() < 2 || commands.len() > 3 {
            println!("Invalid number of arguments. Usage: add <element>");
            return;
        }

        let element = commands[1];

        if commands.len() == 3 && commands[2] == "-h" {
            self.tree.add_data(element.to_string());
        } else {
            self.tree.add_hash(element.to_string());
        }

        println!("{:?} added to the tree.", element);
    }

    fn get_commands(input: &mut String) -> Vec<&str> {
        match io::stdin().read_line(input) {
            Ok(_) => (),
            Err(e) => println!("Failed to read line: {}", e),
        };

        *input = input.trim().to_string();
        input.split(&" ").collect()
    }

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
