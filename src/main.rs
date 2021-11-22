use hex;
use base64;
use hex::FromHexError;
use std::collections::HashMap;
use std::str::from_utf8;

const NUM_LETTERS: usize = 26;
const LETTER_FREQS: [f32; NUM_LETTERS] = [
    0.082, 0.015, 0.028, 0.043, 0.13, 0.022, 0.02, 0.061, 0.07, 0.0015,
    0.0077, 0.04, 0.024, 0.067, 0.075, 0.019, 0.00095, 0.06, 0.063, 0.091,
    0.028, 0.0098, 0.024, 0.0015, 0.02, 0.00074
];

const WILD_PENALTY: f32 = 10.0;

fn hex_to_base64(s: &str) -> Result<String, FromHexError> {
    Ok(base64::encode(hex::decode(s)?))
}

fn xor(a: &str, b: &str) -> Result<String, FromHexError> {
    let a_bytes = hex::decode(a)?;
    let b_bytes = hex::decode(b)?;
    let byte_pairs = a_bytes.iter().zip(b_bytes.iter());
    let xor_bytes: Vec<u8> = byte_pairs.map(|(a_byte, b_byte)| 
        a_byte ^ b_byte).collect();
    Ok(hex::encode(xor_bytes))
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



fn main() {
    println!("{}", crack_one_byte_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crack_one_byte_xor_success() {
        let msg = "1b37373331363f78151b7f2b783431333d\
                   78397828372d363c78373e783a393b3736";
        assert_eq!(crack_one_byte_xor(msg).unwrap(),
                   String::from("Cooking MC's like a pound of bacon"));
        
    }

    #[test]
    fn hex_to_base64_success() {
        let hex_val = "49276d206b696c6c696e6720796f757220627261696e206c\
                       696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64_val = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs\
                          aWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(hex_to_base64(hex_val).unwrap(), String::from(base64_val));
    }

    #[test]
    fn hex_to_base64_fail() {
        let hex_val = "49324af";
        assert_eq!(hex_to_base64(hex_val), Err(FromHexError::OddLength));
    }

    #[test]
    fn xor_success() {
        let a_val = "1c0111001f010100061a024b53535009181c";
        let b_val = "686974207468652062756c6c277320657965";
        let xor_val = "746865206b696420646f6e277420706c6179";
        assert_eq!(xor(a_val, b_val).unwrap(), String::from(xor_val));
    }
}
