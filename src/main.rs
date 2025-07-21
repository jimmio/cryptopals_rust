use encoding_rs::mem::convert_utf8_to_latin1_lossy;
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

fn string_to_bytes(s: &str) -> Vec<u8> {
    let len_in_chars = s.chars().count();
    let utf8_bytes = s.as_bytes();
    let mut u8_bytes = vec![0u8; utf8_bytes.len()];
    convert_utf8_to_latin1_lossy(utf8_bytes, &mut u8_bytes);
    let mut u8_vec = vec![];
    for b in u8_bytes.iter() {
        u8_vec.push(b.clone())
    }
    u8_vec.truncate(len_in_chars);
    u8_vec
}

fn brute_single_byte_xor_cipher(input: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let input_bytes: Vec<u8> = hex_to_bytes(input);
    let keys: Vec<Vec<u8>> = Range{start: 0, end: 254}.map(|b: u8| vec![b]).collect();
    keys
        .iter()
        .map(|k| {
            let plaintext = xor_bytes(&input_bytes, &k);
            (k.clone(), plaintext)
        })
        .collect()
}

fn score_byte(b: &u8) -> f32 {
    let mult = 10.0;
    match b {
        69 | 101 => mult * 12.10,          // E, e
        84 | 116 => mult * 8.94,          // T, t
        65 | 97 => mult * 8.55,           // A, a
        79 | 111 => mult * 7.47,          // O, o
        73 | 105 => mult * 7.33,          // I, i
        78 | 110 => mult * 7.17,          // N, n
        83 | 115 => mult * 6.73,           // S, s
        72 | 104 => mult * 4.96,           // H, h
        82 | 114 => mult * 6.33,           // R, r
        68 | 100 => mult * 3.87,           // D, d
        76 | 108 => mult * 4.21,           // L, l
        85 | 117 => mult * 2.68,           // U, u
        65..=90 | 97..=122 => mult * 1.0,
        _ => -100.0
    }
}

fn score_bytes(bytes: &Vec<u8>) -> i32 {
    let score = bytes
        .iter()
        .map(|b| score_byte(b))
        .sum::<f32>()
        .round();
    score as i32
}

fn highest_scoring_plaintext(keys_plaintexts: &Vec<(Vec<u8>, Vec<u8>)>) -> (Vec<u8>, Vec<u8>) {
    keys_plaintexts
        .iter()
        .map(|kp| {
            (kp, score_bytes(&kp.1))
        })
        .max_by(|kps1, kps2|
                kps1.1.cmp(&kps2.1))
        .unwrap()
        .0
        .clone()
}

#[cfg(test)]

#[test] // Challenge 1
fn test_hex_to_b64() {
    let input: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let bytes: Vec<u8> = hex_to_bytes(input);
    let result: String = bytes_to_b64(bytes);
    assert_eq!(result, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}
#[test]
fn test_number_of_bytes_from_standard_ascii_string_hex() {
    let input: &str = "49276d206b696c6c696e";
    let bytes: Vec<u8> = hex_to_bytes(input);
    assert_eq!(bytes.len(), 10)
}
#[test]
fn test_number_of_bytes_from_standard_ascii_string() {
    let input: &str = "I'm killin";
    let bytes: Vec<u8> = string_to_bytes(input);
    assert_eq!(bytes.len(), 10)
}
#[test]
fn test_number_of_bytes_from_latin_ascii_string_hex() {
    // æÊÎÌËÂæÊÎÌ
    let input: &str = "e6cacecccbc2e6cacecc";
    let bytes: Vec<u8> = hex_to_bytes(input);
    assert_eq!(bytes.len(), 10)
}
#[test]
fn test_number_of_bytes_from_latin_ascii_string() {
    let input: &str = "æÊÎÌËÂæÊÎÌ";
    let bytes: Vec<u8> = string_to_bytes(input);
    assert_eq!(bytes.len(), 10)
}
#[test]
fn test_number_of_bytes_from_mixed_ascii_string() {
    let input: &str = "æbc";
    let bytes: Vec<u8> = string_to_bytes(input);
    assert_eq!(bytes.len(), 3)
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
fn test_break_single_byte_xor_cipher() {
    let input: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let keys_plaintexts: Vec<(Vec<u8>, Vec<u8>)> = brute_single_byte_xor_cipher(&input);
    let highest_scoring: (Vec<u8>, Vec<u8>) = highest_scoring_plaintext(&keys_plaintexts);
    assert_eq!(String::from_utf8(highest_scoring.1).unwrap(), "Cooking MC's like a pound of bacon");
}
#[test]
fn test_scoring_ascii_latin() {
    let input: &str = "æÊ";
    let bytes: Vec<u8> = string_to_bytes(input);
    let score = score_bytes(&bytes);
    assert_eq!(score, -200);
}
#[test]
fn test_scoring_ascii_standard_1() {
    let input: &str = "E";
    let bytes: Vec<u8> = string_to_bytes(input);
    let score = score_bytes(&bytes);
    assert_eq!(score, 121);
}
#[test]
fn test_scoring_ascii_standard_2() {
    let input: &str = "eta";
    let bytes: Vec<u8> = string_to_bytes(input);
    let score = score_bytes(&bytes);
    assert_eq!(score, 296);
}
