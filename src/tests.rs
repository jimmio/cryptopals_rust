use cryptopals::*;
use hamming;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

#[cfg(test)]
mod tests {

    use super::*;

    #[test] // Challenge 1
    fn t_hex_to_b64() {
        let input: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let bytes: Vec<u8> = hex_to_bytes(input);
        let result: String = bytes_to_b64(bytes);
        assert_eq!(
            result,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }
    #[test]
    fn t_number_of_bytes_from_standard_ascii_string_hex() {
        let input: &str = "49276d206b696c6c696e";
        let bytes: Vec<u8> = hex_to_bytes(input);
        assert_eq!(bytes.len(), 10)
    }
    #[test]
    fn t_number_of_bytes_from_standard_ascii_string() {
        let input: &str = "I'm killin";
        let bytes: Vec<u8> = string_to_bytes(input);
        assert_eq!(bytes.len(), 10)
    }
    #[test]
    fn t_number_of_bytes_from_latin_ascii_string_hex() {
        // æÊÎÌËÂæÊÎÌ
        let input: &str = "e6cacecccbc2e6cacecc";
        let bytes: Vec<u8> = hex_to_bytes(input);
        assert_eq!(bytes.len(), 10)
    }
    #[test]
    fn t_number_of_bytes_from_latin_ascii_string() {
        let input: &str = "æÊÎÌËÂæÊÎÌ";
        let bytes: Vec<u8> = string_to_bytes(input);
        assert_eq!(bytes.len(), 10)
    }
    #[test]
    fn t_number_of_bytes_from_mixed_ascii_string() {
        let input: &str = "æbc";
        let bytes: Vec<u8> = string_to_bytes(input);
        assert_eq!(bytes.len(), 3)
    }

    #[test] // Challenge 2
    fn t_xor_bytes() {
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
    fn t_break_single_byte_xor_cipher() {
        let input: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let keys_plaintexts = brute_single_byte_xor_cipher(&input);
        let highest_scoring = highest_scoring_plaintext(&keys_plaintexts);
        assert_eq!(
            String::from_utf8(highest_scoring.1).unwrap(),
            "Cooking MC's like a pound of bacon"
        );
    }
    #[test]
    fn t_scoring_ascii_latin() {
        let input: &str = "æÊ";
        let bytes = string_to_bytes(input);
        let score = score_bytes(&bytes);
        assert_eq!(score, -200);
    }
    #[test]
    fn t_scoring_ascii_mixed() {
        let input: &str = "æÊ ae";
        let bytes = string_to_bytes(input);
        let score = score_bytes(&bytes);
        assert_eq!(score, 17);
    }
    #[test]
    fn t_scoring_ascii_standard_1() {
        let input: &str = "E";
        let bytes: Vec<u8> = string_to_bytes(input);
        let score = score_bytes(&bytes);
        assert_eq!(score, 121);
    }
    #[test]
    fn t_scoring_ascii_standard_2() {
        let input: &str = "eta";
        let bytes = string_to_bytes(input);
        let score = score_bytes(&bytes);
        assert_eq!(score, 296);
    }

    // Challenge 4
    #[test]
    fn t_detect_single_character_xor() {
        let file = File::open("./challenge_files/4.txt").unwrap();
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().map(|l| l.unwrap()).collect();
        let highest_scoring = detect_single_character_xor(lines);
        assert_eq!(
            String::from_utf8(highest_scoring.1).unwrap(),
            "Now that the party is jumping\n"
        );
    }

    // Challenge 5
    #[test]
    fn t_implement_repeating_key_xor() {
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let input_bytes = string_to_bytes(input);
        let key = "ICE";
        let key_bytes = string_to_bytes(key);
        let xord_bytes = xor_bytes(&input_bytes, &key_bytes);
        let xord_hex = bytes_to_hex(xord_bytes);
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(xord_hex, expected);
    }

    // Challenge 6
    #[test]
    fn t_hamming_distance() {
        let s1_bytes = string_to_bytes("this is a test");
        let s2_bytes = string_to_bytes("wokka wokka!!!");
        let expected_dist: u64 = 37;
        let result = hamming::distance(&s1_bytes, &s2_bytes);
        assert_eq!(result, expected_dist);
    }
}
