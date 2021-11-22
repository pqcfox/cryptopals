use std::env;
use std::str::from_utf8;
use std::collections::HashMap;

use base64;
use hex;
use hex::FromHexError;

const WILD_PENALTY: f32 = 10.0;
const NUM_LETTERS: usize = 26;
const LETTER_FREQS: [f32; NUM_LETTERS] = [
    0.082, 0.015, 0.028, 0.043, 0.13, 0.022, 0.02, 0.061, 0.07, 0.0015,
    0.0077, 0.04, 0.024, 0.067, 0.075, 0.019, 0.00095, 0.06, 0.063, 0.091,
    0.028, 0.0098, 0.024, 0.0015, 0.02, 0.00074
];


// Challenge 1: Convert hex to base64

fn hex_to_base64(s: &str) -> Result<String, FromHexError> {
    Ok(base64::encode(hex::decode(s)?))
}


fn challenge_hex_to_base64() {
    let hex_val = "49276d206b696c6c696e6720796f757220627261696e206c\
                   696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let result = hex_to_base64(hex_val).unwrap();
    println!("{}", result);
}

// Challenge 2: Fixed XOR

fn challenge_fixed_xor() {
    let a_val = "1c0111001f010100061a024b53535009181c";
    let b_val = "686974207468652062756c6c277320657965";
    let result = xor(a_val, b_val).unwrap();
    println!("{}", result);
}

fn xor(a: &str, b: &str) -> Result<String, FromHexError> {
    let a_bytes = hex::decode(a)?;
    let b_bytes = hex::decode(b)?;
    let byte_pairs = a_bytes.iter().zip(b_bytes.iter());
    let xor_bytes: Vec<u8> = byte_pairs.map(|(a_byte, b_byte)| 
        a_byte ^ b_byte).collect();
    Ok(hex::encode(xor_bytes))
}

// Challege 3: Single-byte XOR cipher

#[derive(Debug)]
enum CrackError {
    ParseError(FromHexError),
    NoSolutionError
}

impl From<FromHexError> for CrackError {
    fn from(error: FromHexError) -> Self {
        Self::ParseError(error)
    }
}

fn get_letter_counts(s: &str) -> HashMap<char, u32> {
    let mut letter_counts = HashMap::new();
    for ch in s.chars() {
        let key = if ch.is_alphabetic() {
            ch.to_lowercase().next().unwrap()
        } else {
            '*'
        };
        let count = letter_counts.entry(key).or_insert(0);
        *count += 1;
    }
    letter_counts
}

fn score_sentence(s: &str) -> f32 {
    let s_counts = get_letter_counts(s);
    let true_freqs: HashMap<char, f32> = ('a'..='z').zip(LETTER_FREQS).collect();

    let mut score = 0.0;
    for ch in 'a'..='z' {
        let s_count = s_counts.get(&ch).unwrap_or(&0);
        let s_freq = *s_count as f32 / s.len() as f32;
        let diff = s_freq - true_freqs.get(&ch).unwrap();
        score += diff.abs();
    }

    let wild_count = s_counts.get(&'*').unwrap_or(&0);
    let wild_freq = *wild_count as f32 / s.len() as f32;
    score += WILD_PENALTY * wild_freq;
    score
}

fn crack_one_byte_xor(s: &str) -> Result<String, CrackError>{
    let s_bytes = hex::decode(s)?;

    let mut best_score = f32::INFINITY;
    let mut best_msg = Err(CrackError::NoSolutionError);

    for key_val in 0..=255 {
        let result_bytes: Vec<u8> = s_bytes.iter().map(|a|
            a ^ key_val as u8).collect();
        let maybe_decoded = from_utf8(&result_bytes);

        if let Ok(decoded) = maybe_decoded {
            let msg = String::from(decoded);
            let score = score_sentence(&msg);
            if score < best_score {
                best_score = score;
                best_msg = Ok(msg);
            }
        } else {
        }
    }
    best_msg
}

fn challenge_single_byte_xor() {
    let msg = "1b37373331363f78151b7f2b783431333d\
               78397828372d363c78373e783a393b3736";
    let result = crack_one_byte_xor(msg).unwrap();
    println!("{}", result);
}

// Problem selection logic

fn main() {
    let args: Vec<String> = env::args().collect();
    let problem_num = &args[1].parse::<i32>().unwrap();
    match problem_num {
        1 => challenge_hex_to_base64(),
        2 => challenge_fixed_xor(),
        3 => challenge_single_byte_xor(),
        _ => println!("No such problem!")
    }
}
