use std::io::{Read, Write};

use clap;
use sodiumoxide::crypto::secretbox::*;

static KEY: &'static [u8] = include_bytes!("key_file");
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn decode_input(q: usize, id: usize, key: &Key) -> String {
    let mut _nonce_file = std::fs::File::open(format!("data/{}_in_{}_a", q, id)).unwrap();
    let mut nonce = [0_u8; 24];
    _nonce_file.read(&mut nonce).unwrap();
    let _file = std::fs::File::open(format!("data/{}_in_{}_b", q, id)).unwrap();
    let mut decoder = lz4::Decoder::new(_file).unwrap();
    let mut res = Vec::new();
    decoder.read_to_end(&mut res).unwrap();
    let res = open(res.as_slice(), &Nonce(nonce), &key).unwrap();
    String::from_utf8(res).unwrap()
}

fn compare(output: &String, q: usize, id: usize) -> bool {
    let output = output.trim();
    let mut file = std::fs::File::open(format!("data/{}_out_{}", q, id)).unwrap();
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).unwrap();
    argon2::verify_encoded(&buffer, output.as_bytes()).unwrap()
}

fn clap_app<'a, 'b>() -> clap::App<'a, 'b> {
    clap::App::new("assignment4")
        .arg(clap::Arg::with_name("question").short("q").help("question number").value_name("QUESTION")
            .possible_value("1").possible_value("2").required(true))
        .arg(clap::Arg::with_name("source").short("s").help("java source path").value_name("PATH")
            .required(true))
}

fn execute(q: usize, id: usize, key: &Key) {
    println!("Question: {}, #{}", q, id);
    let mut child = std::process::Command::new("java")
        .arg("-classpath")
        .arg("running")
        .arg("Main")
        .arg("server")
        .arg("-Xms128M")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .arg("-Xmx128M")
        .spawn().unwrap();
    let limit = std::time::Duration::from_secs(1);
    let mut stdin = child.stdin.take().unwrap();
    let input = decode_input(q, id, key);
    let start = std::time::SystemTime::now();
    stdin.write_all(input.as_bytes()).expect("unable to write down the input");
    loop {
        match child.try_wait() {
            Ok(None) => {
                let now = std::time::SystemTime::now();
                if now.duration_since(start).unwrap() > limit {
                    child.kill().unwrap();
                    println!("TLE");
                    return;
                }
            }
            Ok(Some(e)) if e.code() == Some(0) => {
                let now = std::time::SystemTime::now();
                println!("Program finished in {} ms", (now.duration_since(start).unwrap()).as_millis());
                break;
            }
            _ => {
                let mut buf = String::new();
                child.stderr.as_mut().unwrap().read_to_string(&mut buf).unwrap();
                println!("RE");
                println!("{}", buf);
                return;
            }
        }
    }
    let mut buf = String::new();
    child.stdout.as_mut().unwrap().read_to_string(&mut buf).unwrap();
    if compare(&buf, q, id) {
        println!("AC")
    } else {
        println!("WA: {}", buf)
    }
}

fn main() {
    let mut _key: [u8; 32] = [0; 32];
    _key.copy_from_slice(KEY);
    match std::fs::remove_dir_all("running") {
        _ => ()
    };
    match std::fs::create_dir("running") {
        _ => ()
    };
    let key = sodiumoxide::crypto::secretbox::Key(_key);
    let app = clap_app();
    let matches = app.get_matches();
    let q: usize = matches.value_of("question").unwrap().parse().unwrap();
    let path = matches.value_of("source").unwrap();
    let mut compile = std::process::Command::new("javac")
        .arg(path).arg("-d").arg("running").spawn().unwrap();
    match compile.wait() {
        Ok(e) if e.code() == Some(0) => (),
        _ =>  {
            println!("CE");
            std::process::exit(0);
        }
    };
    for i in 1..=10 {
        execute(q, i, &key);
    }
}
