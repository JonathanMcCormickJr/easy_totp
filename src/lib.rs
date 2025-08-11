use totp_rs::{Algorithm, TOTP, Secret};

use base64::decode;
use image::DynamicImage;
use std::error::Error;
use std::fmt;
use std::io::{Write, Cursor};

#[derive(Debug)]
struct EasyTotpError<'a>(&'a str);

impl<'a> fmt::Display for EasyTotpError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EasyTotp encuntered an error: {}", self.0)
    }
}

impl <'a> Error for EasyTotpError<'a>{}

impl<'a> EasyTotpError<'a> {
    fn new(message: &'a str) -> Self {
        EasyTotpError(message)
    }
}

pub struct EasyTotp;

impl EasyTotp {
    fn new(raw_secret: String, issuer: Option<String>, account_name: String) -> Result<TOTP, String> {
        let secret;
        let result_secret = Secret::Raw(raw_secret.as_bytes().to_vec()).to_bytes();

        if let Ok(okay_secret) = result_secret {
            secret = okay_secret;
        } else {
            return Err(String::from("Failed to parse secret key"));
        }

        let result = TOTP::new(
            Algorithm::SHA512,
            6,
            1,
            30,
            secret,
            issuer,
            account_name,
        );

        if let Ok(okay_result) = result {
            Ok(okay_result)
        } else {
            Err(String::from("Error creating new TOTP instance"))
        }
    }

    fn create_qr(raw_secret: String, issuer: Option<String>, account_name: String) -> Result<String, Box<dyn Error>> {
        let result = Self::new(raw_secret, issuer, account_name)?.get_qr_base64();
        
        if let Ok(okay_result) = result {
            Ok(okay_result)
        } else {
            Err(Box::new(EasyTotpError::new("Error creating QR code data")))
        }
    }

    pub fn create_qr_png(raw_secret: String, issuer: Option<String>, account_name: String) -> Result<Vec<u8>, Box<dyn Error>> {
        // Decode the base64 string
        let decoded_data = decode(Self::create_qr(raw_secret, issuer, account_name)?)?;
        
        // Create a dynamic image from the decoded data
        let image = image::load_from_memory(&decoded_data)?;
        
        // Write the image to a buffer as a PNG
        let mut buffer = Vec::new();
        let mut cursor = Cursor::new(&mut buffer);
        image.write_to(&mut cursor, image::ImageFormat::Png)?;
        
        Ok(buffer)
    }

    pub fn generate_token(raw_secret: String, issuer: Option<String>, account_name: String) -> Result<String, Box<dyn Error>> {
        Ok(Self::new(raw_secret, issuer, account_name)?.generate_current()?)
    }
}












#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_something() {
        panic!();
    }
}
