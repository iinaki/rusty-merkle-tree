all: test clippy fmt run

test:
	cargo test

clippy:
	cargo clippy

fmt:
	cargo fmt

run:
	cargo run

example-strings:
	cargo run --example strings

example-hashes:
	cargo run --example hashes
