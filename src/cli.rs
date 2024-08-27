use crate::merkle_tree::MerkleTree;
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
                println!("Commands:");
                println!("exit - Exit the program");
                println!(
                    "create <path/to/elements.txt> - Create a new Merkle Tree from a file of elements"
                );
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

    fn handle_create_tree(&mut self, commands: Vec<&str>) {
        if commands.len() != 2 {
            println!("Invalid number of arguments. Usage: create <path/to/elements.txt>");
            return;
        }

        let path = commands[1];
        let elements = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(e) => {
                println!("Failed to read file: {}", e);
                return;
            }
        };

        let elements: Vec<&str> = elements.split("\n").collect();
        let elements: Vec<&str> = elements.iter().map(|element| element.trim()).collect();

        self.tree = MerkleTree::new_from_hasables(elements);
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
        if commands.len() != 2 {
            println!("Invalid number of arguments. Usage: add <element>");
            return;
        }

        let element = commands[1];
        self.tree.add_hash(element.to_string());
        println!("{:?} added to the tree.", element);
    }

    pub fn run(&mut self) {
        // read file with hashes, get file path from user
        // console-based menu that lets user:
        //     - see if tx hash included in tree
        //     - see proof of inclusion for tx hash
        //     - add tx hash to tree
        println!("Welcome to the Merkle Tree CLI, type 'help' to see the list of commands.");

        let mut input = "".to_string();
        let mut running = true;

        while running {
            match io::stdin().read_line(&mut input) {
                Ok(_) => (),
                Err(e) => println!("Failed to read line: {}", e),
            };

            input = input.trim().to_string();
            let commands: Vec<&str> = input.split(&" ").collect();

            self.manage_input(commands, &mut running);

            input.clear();
        }
    }
}
