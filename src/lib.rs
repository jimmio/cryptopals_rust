use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use base64::prelude::*;
use encoding_rs::mem::convert_utf8_to_latin1_lossy;
use hex::FromHex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::Range;

pub fn hex_file_to_bytes(filepath: &str) -> Vec<Vec<u8>> {
    let file = File::open(filepath).expect("Unable to open file.");
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().map(|l| l.unwrap()).collect();
    lines.iter().map(|l| hex_to_bytes(l)).collect()
}

pub fn b64_file_to_bytes(filepath: &str) -> Vec<u8> {
    let file = File::open(filepath).expect("Unable to open file.");
    let reader = BufReader::new(file);
    let b64: String = reader.lines().map(|l| l.unwrap()).collect();
    b64_to_bytes(&b64)
}

pub fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    Vec::<u8>::from_hex(hex_str).expect("Unable to convert hex string to Vec<u8>.")
}

pub fn bytes_to_hex(bytes: Vec<u8>) -> String {
    hex::encode(bytes)
}

pub fn bytes_to_b64(bytes: Vec<u8>) -> String {
    BASE64_STANDARD.encode(bytes)
}

pub fn b64_to_bytes(s: &str) -> Vec<u8> {
    BASE64_STANDARD.decode(s).unwrap()
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

pub fn brute_single_byte_xor_cipher(input_bytes: &Vec<u8>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let keys: Vec<Vec<u8>> = Range { start: 0, end: 254 }.map(|b: u8| vec![b]).collect();
    keys.iter()
        .map(|k| {
            let plaintext = xor_bytes(&input_bytes, k);
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
        _ => -100.0,
    }
}

pub fn score_bytes(bytes: &Vec<u8>) -> i32 {
    let score = bytes.iter().map(|b| score_byte(b)).sum::<f32>().round();
    score as i32
}

pub fn highest_scoring_plaintext(
    keys_plaintexts: &Vec<(Vec<u8>, Vec<u8>)>,
) -> (Vec<u8>, Vec<u8>, i32) {
    // returns (key, plaintext, score)
    keys_plaintexts
        .iter()
        .map(|kp| (kp.0.clone(), kp.1.clone(), score_bytes(&kp.1)))
        .max_by(|kps_x, kps_y| kps_x.2.cmp(&kps_y.2))
        .unwrap()
        .clone()
}

pub fn break_single_character_xor(input_bytes: Vec<Vec<u8>>) -> (Vec<u8>, Vec<u8>, i32) {
    input_bytes
        .iter()
        .map(|v| highest_scoring_plaintext(&brute_single_byte_xor_cipher(v)))
        .max_by(|kps_x, kps_y| kps_x.2.cmp(&kps_y.2))
        .unwrap()
        .clone()
}

pub fn guess_xor_keysize(input_bytes: &Vec<u8>) -> Vec<u32> {
    let mut sizes_distances: Vec<(u32, u32)> = vec![];
    let sizes: Vec<usize> = (2usize..=60).collect();
    for keysize in sizes {
        let keysize_u32 = keysize as u32;
        let chunks: Vec<_> = input_bytes.chunks(keysize).take(8).collect();
        let avg = (0..3)
            .map(|i| hamming::distance(chunks[i], chunks[i + 1]) as u32 / keysize_u32)
            .sum::<u32>()
            / 4;
        sizes_distances.push((keysize_u32, avg));
    }
    sizes_distances.sort_by(|kd1, kd2| kd1.1.cmp(&kd2.1));
    sizes_distances
        .into_iter()
        .take(10)
        .clone()
        .map(|tup| tup.0)
        .collect()
}

pub fn partition(input_bytes: &Vec<u8>, size: &u32) -> Vec<Vec<u8>> {
    input_bytes
        .chunks(*size as usize)
        .map(|chunk| chunk.to_vec())
        .collect()
}

pub fn transpose(bytes: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    // Assume that all inner vecs will be of the same length
    // except for (possibly) the last
    let vec_len = bytes[0].len();
    let mut transposed: Vec<Vec<u8>> = vec![];
    for i in 0..vec_len {
        let tv: Vec<u8> = bytes
            .iter()
            .map(|v| match v.get(i) {
                Some(b) => b.to_owned(),
                // Return 0 for missing indices
                None => 0,
            })
            .collect();
        transposed.push(tv);
    }
    transposed
}

pub fn break_repeating_key_xor(input_bytes: &Vec<u8>, keysizes: Vec<u32>) -> (Vec<u8>, Vec<u8>) {
    let mut keysize_results: Vec<Vec<(Vec<u8>, Vec<u8>, i32)>> = vec![];
    for keysize in keysizes {
        let partitioned = partition(&input_bytes, &keysize);
        let transposed = transpose(&partitioned);
        let keys_plaintexts: Vec<Vec<(Vec<u8>, Vec<u8>)>> = transposed
            .iter()
            .map(|v| brute_single_byte_xor_cipher(v))
            .collect();
        let keys_plaintexts_scores: Vec<(Vec<u8>, Vec<u8>, i32)> = keys_plaintexts
            .iter()
            .map(|v| highest_scoring_plaintext(&v))
            .collect();
        keysize_results.push(keys_plaintexts_scores);
    }
    // in keysize_results, each inner vector one layer deep contains the kps for each single byte xor for a given keysize
    let repeating_keys: Vec<Vec<u8>> = keysize_results
        .iter()
        .map(|v| {
            v.iter()
                .map(|(single_byte_key, _, _)| single_byte_key.clone())
                .flatten()
                .collect()
        })
        .collect();
    let avg_scores: Vec<i32> = keysize_results
        .iter()
        .map(|v| v.iter().map(|(_, _, score)| score).sum::<i32>() / v.len() as i32)
        .collect();
    let key: Vec<u8> = itertools::izip!(repeating_keys, avg_scores)
        .max_by(|(_, score_a), (_, score_b)| score_a.cmp(&score_b))
        .unwrap()
        .0;
    (key.to_owned(), xor_bytes(&input_bytes, &key))
}

pub fn decrypt_aes_128_block(input_bytes: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut input_bytes_mut = *GenericArray::from_slice(&input_bytes);
    let key_arr = GenericArray::from_slice(&key);
    let cipher = Aes128::new(&key_arr);
    cipher.decrypt_block(&mut input_bytes_mut);
    input_bytes_mut.to_vec()
}

pub fn encrypt_aes_128_block(input_bytes: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut input_bytes_mut = *GenericArray::from_slice(&input_bytes);
    let key_arr = GenericArray::from_slice(&key);
    let cipher = Aes128::new(&key_arr);
    cipher.encrypt_block(&mut input_bytes_mut);
    input_bytes_mut.to_vec()
}

pub fn decrypt_aes_128_ecb(input_bytes: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let partitioned: Vec<Vec<u8>> = partition(input_bytes, &16u32);
    partitioned
        .iter()
        .map(|v| decrypt_aes_128_block(v, key))
        .flatten()
        .collect()
}

pub fn encrypt_aes_128_ecb(input_bytes: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let partitioned: Vec<Vec<u8>> = partition(input_bytes, &16u32);
    partitioned
        .iter()
        .map(|v| encrypt_aes_128_block(v, key))
        .flatten()
        .collect()
}

pub fn detect_ecb(enc_bytes: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut partitioned: Vec<Vec<Vec<u8>>> =
        enc_bytes.iter().map(|v| partition(&v, &16u32)).collect();
    let mut ecb_blocks: Vec<Vec<u8>> = vec![];
    for v in partitioned.iter_mut() {
        let initial_v = v.clone();
        v.sort();
        v.dedup();
        if v.len() != initial_v.len() {
            ecb_blocks.push(initial_v.into_iter().flatten().collect());
        }
    }
    ecb_blocks
}

pub fn pkcs7_pad_block(input_bytes: Vec<u8>, desired_block_size: u8) -> Vec<u8> {
    let diff: u8 = desired_block_size - input_bytes.len() as u8;
    if diff > 0 {
        let mut bytes_mut_a: Vec<u8> = input_bytes.clone();
        let mut bytes_mut_b: Vec<u8> = vec![diff; diff as usize];
        bytes_mut_a.append(&mut bytes_mut_b);
        bytes_mut_a
    } else {
        input_bytes
    }
}

pub fn pkcs7_pad(input_bytes: Vec<u8>, desired_block_size: u8) -> Vec<u8> {
    let diff: u8 = desired_block_size - (input_bytes.len() as u8 % desired_block_size);
    if diff > 0 {
        let mut bytes_mut_a: Vec<u8> = input_bytes.clone();
        let mut bytes_mut_b: Vec<u8> = vec![diff; diff as usize];
        bytes_mut_a.append(&mut bytes_mut_b);
        bytes_mut_a
    } else {
        input_bytes
    }
}

pub fn decrypt_aes_128_cbc(input_bytes: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    // for each block, decrypt then xor that plaintext against the previous ciphertext block
    let mut iv_mut: Vec<u8> = iv.clone();
    let mut input_bytes_mut: Vec<u8> = input_bytes.clone();
    iv_mut.append(&mut input_bytes_mut);
    let partitioned = partition(&iv_mut, &16u32);
    let mut cbc_decrypted: Vec<Vec<u8>> = vec![];
    for i in 1..partitioned.len() {
        let aes_decrypted = decrypt_aes_128_block(&partitioned[i], &key);
        let xord = xor_bytes(&aes_decrypted, partitioned.get(i - 1).unwrap());
        cbc_decrypted.push(xord);
    }
    cbc_decrypted.into_iter().flatten().collect()
}

pub fn rand_bytes() -> Vec<u8> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("Unable to obtain bytes.");
    buf.to_vec()
}
