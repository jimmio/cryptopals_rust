use hex::FromHex;
use base64::prelude::*;
use std::ops::Range;

fn main() {
    
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

fn xor_bytes(input: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    input
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % key.len()])
        .collect()
}

fn brute_single_byte_xor_cipher(input: &str) -> Vec<Vec<u8>> {
    let input_bytes: Vec<u8> = hex_to_bytes(input);
    let key_candidates: Vec<Vec<u8>> = Range{start: 0, end: 254}.map(|b| vec![b]).collect();
    key_candidates
        .iter()
        .map(|k| xor_bytes(&input_bytes, k))
        .collect()
}

fn score_byte(b: &u8) -> u32 {
    match b {
        69 | 101 => 15,          // E, e
        84 | 116 => 14,          // T, t
        65 | 97 => 13,           // A, a
        79 | 111 => 12,          // O, o
        73 | 105 => 11,          // I, i
        78 | 110 => 10,          // N, n
        83 | 115 => 9,           // S, s
        72 | 104 => 8,           // H, h
        82 | 114 => 7,           // R, r
        68 | 100 => 6,           // D, d
        76 | 108 => 5,           // L, l
        85 | 117 => 4,           // U, u
        65..=90 | 97..=122 => 1,
        _ => 0
    }
}

fn score_bytes(bytes: &Vec<u8>) -> u32 {
    bytes
        .iter()
        .map(|b| score_byte(b))
        .sum()
}

fn highest_scoring_plaintext(plaintexts: &Vec<Vec<u8>>) -> u32 {
    plaintexts
        .iter()
        .map(|v| score_bytes(v))
        .max_by(|x, y| x.cmp(&y))
        .unwrap()
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
    let result_bytes: Vec<u8> = xor_bytes(&input_bytes, &key_bytes);
    let result: String = bytes_to_hex(result_bytes);
    assert_eq!(result, "746865206b696420646f6e277420706c6179");
}

// Challenge 3
#[test]
fn test_single_byte_xor_cipher_plaintext() {
    // let input: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    // let result: Vec<Vec<u8>> = brute_single_byte_xor_cipher(&input);
    // assert_eq!(vec![vec![1]], result);

}
#[test]
fn test_single_byte_xor_cipher_score() {
    let input: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let plaintexts: Vec<Vec<u8>> = brute_single_byte_xor_cipher(&input);
    let highest_score: u32 = highest_scoring_plaintext(&plaintexts);
    assert_eq!(highest_score, 30);
}
#[test]
fn test_scoring() {
    
}
