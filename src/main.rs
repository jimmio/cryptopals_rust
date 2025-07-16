use hex::FromHex;
use base64::prelude::*;

fn main() {
    println!("Hello, world!");
}

fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    Vec::<u8>::from_hex(hex_str).expect("Unable to convert hex string to Vec<u8>.")
}

fn bytes_to_b64(bytes: &Vec<u8>) -> String {
    BASE64_STANDARD.encode(bytes)
}

#[cfg(test)]
#[test] // Challenge 1
fn test_hex_to_b64() {
    let input: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let bytes: Vec<u8> = hex_to_bytes(input);
    let result: String = bytes_to_b64(&bytes);
    assert_eq!(result, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}
