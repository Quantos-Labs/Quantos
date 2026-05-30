use sha3::{Digest, Keccak256};

fn main() {
    let mut hasher = Keccak256::new();
    hasher.update(b"deposit(bytes32,uint256)");
    let res = hasher.finalize();
    println!("{:x}", res);
}
