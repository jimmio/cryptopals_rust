use cryptopals::*;

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
        let input_bytes: Vec<u8> = hex_to_bytes(input);
        let keys_plaintexts = brute_single_byte_xor_cipher(&input_bytes);
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
        let lines_as_bytes = hex_file_to_bytes("./challenge_files/4.txt");
        let highest_scoring = break_single_character_xor(lines_as_bytes);
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

    #[test]
    fn t_break_repeating_key_xor() {
        let input_bytes: Vec<u8> = b64_file_to_bytes("./challenge_files/6.txt");
        let keysizes = guess_xor_keysize(&input_bytes);
        assert_eq!(keysizes, vec![2, 3, 5, 13, 18, 29, 58, 4, 6, 7]);
        let key_plaintext_score = break_repeating_key_xor(&input_bytes, keysizes);
        let key_str = String::from_utf8(key_plaintext_score.0).unwrap();
        let plaintext_str = String::from_utf8(key_plaintext_score.1).unwrap();
        assert_eq!(key_str, "Terminator X: Bring the noise");
        assert_eq!(
            plaintext_str,
            "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"
        );
    }

    #[test]
    fn t_partition() {
        let v: Vec<u8> = (0u8..=21).collect();
        let size = 5;
        let partitioned = partition(&v, &size);
        assert_eq!(
            partitioned,
            vec![
                vec![0, 1, 2, 3, 4],
                vec![5, 6, 7, 8, 9],
                vec![10, 11, 12, 13, 14],
                vec![15, 16, 17, 18, 19],
                vec![20, 21]
            ]
        );
    }

    #[test]
    fn t_transpose() {
        let v: Vec<Vec<u8>> = vec![
            vec![0, 1, 2, 3, 4],
            vec![5, 6, 7, 8, 9],
            vec![10, 11, 12, 13, 14],
            vec![15, 16, 17, 18, 19],
            vec![20, 21],
        ];
        let transposed = transpose(&v);
        assert_eq!(
            transposed,
            vec![
                vec![0, 5, 10, 15, 20],
                vec![1, 6, 11, 16, 21],
                vec![2, 7, 12, 17, 0],
                vec![3, 8, 13, 18, 0],
                vec![4, 9, 14, 19, 0]
            ]
        );
        let transposed_again = transpose(&transposed);
        // transpose() is reversible, but will include trailing null bytes
        assert_eq!(
            transposed_again,
            vec![
                vec![0, 1, 2, 3, 4],
                vec![5, 6, 7, 8, 9],
                vec![10, 11, 12, 13, 14],
                vec![15, 16, 17, 18, 19],
                vec![20, 21, 0, 0, 0],
            ]
        );
    }

    #[test]
    fn t_decrypt_ecb() {
        let input_bytes: Vec<u8> = b64_file_to_bytes("./challenge_files/7.txt");
        let key: &str = "YELLOW SUBMARINE";
        let key_bytes = string_to_bytes(&key);
        let decrypted = decrypt_aes_128_ecb(&input_bytes, &key_bytes);
        let decrypted_str = String::from_utf8(decrypted).unwrap();
        assert_eq!(
            decrypted_str,
            "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}"
        );
    }

    #[test]
    fn t_encrypt_ecb() {
        let input: &str = "foobarbazquxfoo!";
        let input_bytes: Vec<u8> = string_to_bytes(input);
        let key: &str = "YELLOW SUBMARINE";
        let key_bytes = string_to_bytes(&key);
        let encrypted = encrypt_aes_128_ecb(&input_bytes, &key_bytes);
        assert_eq!(
            encrypted,
            vec![
                219, 162, 245, 104, 236, 140, 11, 66, 3, 164, 170, 183, 53, 103, 47, 32
            ]
        );
    }

    #[test]
    fn t_encrypt_ecb_2() {
        let input: &str = "foobarbazquxfoo!foobarbazquxfoo!";
        let input_bytes: Vec<u8> = string_to_bytes(input);
        let key: &str = "YELLOW SUBMARINE";
        let key_bytes = string_to_bytes(&key);
        let encrypted = encrypt_aes_128_ecb(&input_bytes, &key_bytes);
        assert_eq!(
            encrypted,
            vec![
                219, 162, 245, 104, 236, 140, 11, 66, 3, 164, 170, 183, 53, 103, 47, 32, 219, 162,
                245, 104, 236, 140, 11, 66, 3, 164, 170, 183, 53, 103, 47, 32
            ]
        );
    }

    #[test]
    fn t_roundtrip_ecb() {
        let input: &str = "foobarbazquxfoo!foobarbazquxfoo!";
        let input_bytes: Vec<u8> = string_to_bytes(input);
        let key: &str = "YELLOW SUBMARINE";
        let key_bytes = string_to_bytes(&key);
        let encrypted = encrypt_aes_128_ecb(&input_bytes, &key_bytes);
        let decrypted = decrypt_aes_128_ecb(&encrypted, &key_bytes);
        let decrypted_string = String::from_utf8(decrypted).unwrap();
        assert_eq!(input, decrypted_string);
    }

    #[test]
    fn t_detect_ecb() {
        let enc_bytes = hex_file_to_bytes("./challenge_files/8.txt");
        let result = detect_ecb(enc_bytes);
        assert_eq!(
            result,
            vec![[
                216, 128, 97, 151, 64, 168, 161, 155, 120, 64, 168, 163, 28, 129, 10, 61, 8, 100,
                154, 247, 13, 192, 111, 79, 213, 210, 214, 156, 116, 76, 210, 131, 226, 221, 5, 47,
                107, 100, 29, 191, 157, 17, 176, 52, 133, 66, 187, 87, 8, 100, 154, 247, 13, 192,
                111, 79, 213, 210, 214, 156, 116, 76, 210, 131, 148, 117, 201, 223, 219, 193, 212,
                101, 151, 148, 157, 156, 126, 130, 191, 90, 8, 100, 154, 247, 13, 192, 111, 79,
                213, 210, 214, 156, 116, 76, 210, 131, 151, 169, 62, 171, 141, 106, 236, 213, 102,
                72, 145, 84, 120, 154, 107, 3, 8, 100, 154, 247, 13, 192, 111, 79, 213, 210, 214,
                156, 116, 76, 210, 131, 212, 3, 24, 12, 152, 200, 246, 219, 31, 42, 63, 156, 64,
                64, 222, 176, 171, 81, 178, 153, 51, 242, 193, 35, 197, 131, 134, 176, 111, 186,
                24, 106
            ]]
        );
    }
    #[test]
    fn t_detect_ecb_2() {
        let enc_bytes: Vec<Vec<u8>> =
            vec![vec![1u8; 16], vec![2u8; 16], vec![3u8; 16], vec![4u8; 16]];
        let result: Vec<Vec<u8>> = detect_ecb(enc_bytes);
        let empty: Vec<Vec<u8>> = vec![];
        assert_eq!(result, empty);
    }
    #[test]
    fn t_pkcs7_pad_block() {
        let input_bytes: Vec<u8> = vec![1, 2, 3, 4];
        let block_size: u8 = 16;
        let result = pkcs7_pad_block(input_bytes, block_size);
        let expected: Vec<u8> = vec![1, 2, 3, 4, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12];
        assert_eq!(result, expected);
    }
    #[test]
    fn t_pkcs7_pad_block_2() {
        let input_bytes: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let block_size: u8 = 16;
        let result = pkcs7_pad_block(input_bytes, block_size);
        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert_eq!(result, expected);
    }
    #[test]
    fn t_pkcs7_pad_block_3() {
        let input_bytes: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let block_size: u8 = 16;
        let result = pkcs7_pad_block(input_bytes, block_size);
        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1];
        assert_eq!(result, expected);
    }

    #[test]
    fn t_pkcs7_padding_multiple() {
        let input_bytes: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30,
        ];
        let block_size: u8 = 16;
        let result = pkcs7_pad(input_bytes, block_size);
        let expected: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 2, 2,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn t_decrypt_aes_128_cbc() {
        let input_bytes = b64_file_to_bytes("./challenge_files/10.txt");
        let key: &str = "YELLOW SUBMARINE";
        let key_bytes = string_to_bytes(&key);
        let iv_bytes = vec![0; 16];
        let decrypted = decrypt_aes_128_cbc(&input_bytes, &key_bytes, &iv_bytes);
        let decrypted_str = String::from_utf8(decrypted).unwrap();
        assert_eq!(
            decrypted_str,
            "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}"
        );
    }
}
