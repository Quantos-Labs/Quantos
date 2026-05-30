use pqcrypto_dilithium::dilithium3;

fn main() {
    let (pk, sk) = dilithium3::keypair();
    println!("PK size: {}", pk.as_bytes().len());
    println!("SK size: {}", sk.as_bytes().len());
}
