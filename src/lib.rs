use encoding_rs::mem::convert_utf8_to_latin1_lossy;
use hex::FromHex;
use base64::prelude::*;
use std::ops::Range;

pub fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    Vec::<u8>::from_hex(hex_str).expect("Unable to convert hex string to Vec<u8>.")
}

pub fn bytes_to_hex(bytes: Vec<u8>) -> String {
    hex::encode(bytes)
}

pub fn bytes_to_b64(bytes: Vec<u8>) -> String {
    BASE64_STANDARD.encode(bytes)
}

pub fn xor_bytes(input: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    input
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % key.len()])
        .collect()
}

pub fn string_to_bytes(s: &str) -> Vec<u8> {
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

pub fn brute_single_byte_xor_cipher(input: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
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

pub fn score_byte(b: &u8) -> f32 {
    let mult = 10.0;
    match b {
        69 | 101 => mult * 12.10, // E, e
        84 | 116 => mult * 8.94,  // T, t
        65 | 97 => mult * 8.55,   // A, a
        79 | 111 => mult * 7.47,  // O, o
        73 | 105 => mult * 7.33,  // I, i
        78 | 110 => mult * 7.17,  // N, n
        83 | 115 => mult * 6.73,  // S, s
        72 | 104 => mult * 4.96,  // H, h
        82 | 114 => mult * 6.33,  // R, r
        68 | 100 => mult * 3.87,  // D, d
        76 | 108 => mult * 4.21,  // L, l
        85 | 117 => mult * 2.68,  // U, u
        // Remaining alphabet and spaces
        65..=90 | 97..=122 | 32 => mult * 1.0,
        // Everything else
        _ => -100.0
    }
}

pub fn score_bytes(bytes: &Vec<u8>) -> i32 {
    let score = bytes
        .iter()
        .map(|b| score_byte(b))
        .sum::<f32>()
        .round();
    score as i32
}

pub fn highest_scoring_plaintext(keys_plaintexts: &Vec<(Vec<u8>, Vec<u8>)>) -> (Vec<u8>, Vec<u8>) {
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
