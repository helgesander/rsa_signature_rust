use::std::io;
use rsa::RsaPrivateKey;
use rsa::pkcs8::der::Writer;
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::pss::SigningKey;
use sha2::Sha256;

fn main() {
    print!("Enter string: ");
    let mut _data = String::new();
    io::stdin()
        .read_line(&mut _data)
        .expect("Failed to read line");
    let mut buffer = [0; 32];
    let mut data: &mut[u8] = &mut buffer;
    data.write(_data.as_bytes()).unwrap();
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign_with_rng(&mut rng, data);
    verifying_key.verify(data, &signature).expect("failed to verify");
    println!("Signature: {signature}");
}