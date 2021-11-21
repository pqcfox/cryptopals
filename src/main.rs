use hex;
use base64;
use hex::FromHexError;

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

fn main() {
    println!("{}", xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965").unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

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
