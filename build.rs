use std::io::{Result, Write, Read};
use uuid;
use sodiumoxide::crypto::secretbox::*;
fn hash_out(output: &str) -> String {
    let output = output.trim().as_bytes();
    let salt = uuid::Uuid::new_v4();
    let config = argon2::Config::default();
    argon2::hash_encoded(output, salt.as_bytes(), &config).unwrap()
}
fn gen_encoded(key: &Key, q: usize, id: usize) -> Result<()> {
    let nonce = gen_nonce();
    let mut out_input =  std::fs::File::open(format!("{}/{}.in", q, id))?;
    let mut nonce_file = std::fs::File::create(format!("data/{}_in_{}_a", q, id))?;
    let res_file = std::fs::File::create(format!("data/{}_in_{}_b", q, id))?;
    nonce_file.write_all(&nonce.0)?;
    let mut buffer = String::new();
    out_input.read_to_string(&mut buffer)?;
    let content = seal(buffer.as_bytes(), &nonce, key);
    let mut encoder = lz4::EncoderBuilder::new().level(4).build(res_file)?;
    encoder.write_all(content.as_slice())?;
    encoder.flush()?;
    Ok(())
}
fn main() -> Result<()> {
    match std::fs::remove_dir_all("data") {_ => ()};
    match std::fs::create_dir("data") {_ => ()};
    let key = gen_key();
    let mut key_file = std::fs::File::create("src/key_file")?;
    key_file.write_all(&key.0)?;
    for j in [1, 2].iter() {
        for i in 1..=10 {
            let out_filename = format!("{}/{}.out", j, i);
            let output_encoded = format!("data/{}_out_{}", j, i);
            let mut out_input = std::fs::File::open(out_filename)?;
            let mut buffer = String::new();
            out_input.read_to_string(&mut buffer)?;
            let mut file = std::fs::File::create(output_encoded)?;
            file.write_all(hash_out(buffer.as_str()).as_bytes())?;
            gen_encoded(&key, *j, i)?;
        }
    }
    Ok(())
}