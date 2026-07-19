use pqcrypto_mldsa::mldsa65;

fn main() {
    let (pk, sk) = mldsa65::keypair();
    println!("PK size: {}", pk.as_bytes().len());
    println!("SK size: {}", sk.as_bytes().len());
}
