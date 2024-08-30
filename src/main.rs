use rusty_merkle_tree::cli::CLI;

fn main() {
    let mut cli = match CLI::new() {
        Ok(cli) => cli,
        Err(e) => {
            println!("Failed to create CLI: {:?}", e);
            return;
        }
    };
    cli.run();
}
