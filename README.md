# Rusty Merkle Tree

### How to run
- Clone the repository with `git clone`.
- To run the program, enter the directory containing the Merkle Tree files and run `make run`, you can also run `cargo run`.
- Additionaly you can run `make all` to run the program and also run the tests, run clippy and format the code.
- Use `make test` to run the tests, use `make fmt` to format the code and `make clippy` to run clippy.

### How to use
By running the program you will enter the interactive CLI. To view the available commands type `help`, they are:
- `create <path/to/elements.txt> <--hash>`, creates a new Merkle Tree from the elements in the file, it is assumed that the elements in the file are hashed, if the `--hash` flag is passed the elements will be hashed before being added to the tree.
- `show`, displays the current Merkle Tree.
- `verify <element> <index>`, verifies if the given element is present in the Merkle Tree. The parameter `index` is optional, and if passed the program will verify if the element is present in the given index, and reducing the time of the verification to O(log n).
- `proof <element> <index>`, generates a proof of inclusion for the given element. The parameter `index` is optional, and if passed the program will obtain the Proof of Inclusion if the element is present in the given index, and reducing the time of the proof to O(log n).
- `add <element> <--hash>`, adds a new element to the Merkle Tree, if the `--hash` flag is passed the element will be hashed before being added to the tree.
- `exit`, exits the program.

To create a Merkle Tree you have to pass the program a file with the hashes/elements that you want the tree to store. The program doesn't check wheather the hashes are valid or not, it assumes that the hashes are valid SHA256.

### Examples
I've included two files in the examples directory, one with hashes and one with strings for you to test.
- You can run them with: `make example-hashes` and `make example-strings`.

### Merkle Proof of Inclusion
Merkle proofs are used to decide upon the following factors:

- If the data belongs in the merkle tree
- To concisely prove the validity of data being part of a dataset without storing the whole data set
- To ensure the validity of a certain data set being inclusive in a larger data set without revealing either the complete data set or its subset.

![alt text](img/proof-of-inclusion.png)
In order to verify the inclusion of data [K], in the merkle tree root, we use a one way function to hash [K] to obtain H(K).
In order to obtain a merkle proof of H(K), we need H(L), H(IJ), H(MNOP) and H(ABCDEFGH) with which we can together obtain H(ABCDEFHGIJKLMNOP) hence proving that H(K) was part of the merkle tree implying that data set K was indeed part of the universal dataset [A, B, C, … , N, O, P].
