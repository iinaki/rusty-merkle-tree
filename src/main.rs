use std::{io, vec};

use rusty_merkle_tree::merkle_tree::MerkleTree;

pub fn manage_input(commands: Vec<&str>, running: &mut bool, tree: &mut MerkleTree) {
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
            handle_create_tree(commands, tree);
        }
        "show" => {
            tree.print();
        }
        "verify" => {
            handle_verify_inclusion(commands, tree);
        }
        "proof" => {
            handle_proof_of_inclusion(commands, tree);
        }
        "add" => {
            handle_add_element(commands, tree);
        }
        _ => {
            println!("Invalid command. Type 'help' to see the list of commands.");
        }
    }
}

pub fn handle_create_tree(commands: Vec<&str>, tree: &mut MerkleTree) {
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

    *tree = MerkleTree::new_from_hasables(elements);
    println!(
        "Merkle Tree created from file: {:?}, use 'show' to view te current tree.",
        path
    );
}

pub fn handle_verify_inclusion(commands: Vec<&str>, tree: &MerkleTree) {
    if commands.len() != 2 {
        println!("Invalid number of arguments. Usage: verify <element>");
        return;
    }

    let element = commands[1];

    if tree.verify(element.to_string()) {
        println!("{:?} is included in the tree.", element);
    } else {
        println!("{:?} is not included in the tree.", element);
    }
}

fn main() {
    // read file with hashes, get file path from user
    // console-based menu that lets user:
    //     - see if tx hash included in tree
    //     - see proof of inclusion for tx hash
    //     - add tx hash to tree

    println!("Welcome to the Merkle Tree CLI!");
    println!("Type 'help' to see the list of commands.");

    let mut input = "".to_string();
    let mut running = true;
    let mut tree = MerkleTree::new_from_hasables(vec![""]);

    while running {
        println!("Enter command: ");
        match io::stdin().read_line(&mut input) {
            Ok(_) => (),
            Err(e) => println!("Failed to read line: {}", e),
        };

        input = input.trim().to_string();
        let commands: Vec<&str> = input.split(&" ").collect();

        manage_input(commands, &mut running, &mut tree);

        input.clear();
    }
}
