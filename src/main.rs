use hex::FromHex;
use base64::prelude::*;

fn main() {
    println!("Hello, world!");
}

fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    Vec::<u8>::from_hex(hex_str).expect("Unable to convert hex string to Vec<u8>.")
}

fn bytes_to_hex(bytes: Vec<u8>) -> String {
    hex::encode(bytes)
}

fn bytes_to_b64(bytes: Vec<u8>) -> String {
    BASE64_STANDARD.encode(bytes)
}

fn xor_bytes(input: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    input
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % key.len()])
        .collect()
}

#[cfg(test)]

#[test] // Challenge 1
fn test_hex_to_b64() {
    let input: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let bytes: Vec<u8> = hex_to_bytes(input);
    let result: String = bytes_to_b64(bytes);
    assert_eq!(result, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

#[test] // Challenge 2
fn test_xor_bytes() {
    let input: &str = "1c0111001f010100061a024b53535009181c";
    let key: &str = "686974207468652062756c6c277320657965";
    let input_bytes: Vec<u8> = hex_to_bytes(input);
    let key_bytes: Vec<u8> = hex_to_bytes(key);
    let result_bytes: Vec<u8> = xor_bytes(input_bytes, key_bytes);
    let result: String = bytes_to_hex(result_bytes);
    assert_eq!(result, "746865206b696420646f6e277420706c6179");
}
