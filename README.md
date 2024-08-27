# Rusty Merkle Tree

### How to run
- Clone the repository with git clone
- Enter the directory containing the Merkle Tree files and run `cargo run`

### How to use
By running the program you will enter the interactive CLI. To view the available commands type `help`, they are:
- `create <path/to/elements.txt> <-h>`, creates a new Merkle Tree from the elements in the file, it is assumed that the elements in the file are hashed, if the -h flag is passed the elements will be hashed before being added to the tree.
- `show`, displays the current Merkle Tree.
- `verify <element>`, verifies if the given element is present in the Merkle Tree.
- `proof <element>`, generates a proof of inclusion for the given element.
- `add <element> <-h>`, adds a new element to the Merkle Tree, if the -h flag is passed the element will be hashed before being added to the tree.
- `exit`, exits the program.

### Merkle Proof of Inclusion
Merkle proofs are used to decide upon the following factors:

- If the data belongs in the merkle tree
- To concisely prove the validity of data being part of a dataset without storing the whole data set
- To ensure the validity of a certain data set being inclusive in a larger data set without revealing either the complete data set or its subset.

![alt text](img/proof-of-inclusion.png)
In order to verify the inclusion of data [K], in the merkle tree root, we use a one way function to hash [K] to obtain H(K).
In order to obtain a merkle proof of H, we need H(L), H(IJ), H(MNOP) and H(ABCDEFGH) with which we can together obtain H(ABCDEFHGIJKLMNOP) hence proving that H(K) was part of the merkle tree implying that data set K was indeed part of the universal dataset [A, B, C, … , N, O, P].
