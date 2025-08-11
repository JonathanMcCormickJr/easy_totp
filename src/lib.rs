#![deny(missing_docs)]
#![deny(unsafe_code)]

//! `easy_totp` is a crate designed to make it easy to integrate TOTP into your Rust apps.

use totp_rs::{Algorithm, Secret, TOTP};

use base64::decode;
use std::error::Error;
use std::fmt;
use std::io::Cursor;

#[derive(Debug)]
struct EasyTotpError<'a>(&'a str);

impl<'a> fmt::Display for EasyTotpError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EasyTotp encuntered an error: {}", self.0)
    }
}

impl<'a> Error for EasyTotpError<'a> {}

impl<'a> EasyTotpError<'a> {
    fn new(message: &'a str) -> Self {
        EasyTotpError(message)
    }
}

/// `EasyTotp` is a unit-struct to keep track of externally-implemented code.
pub struct EasyTotp;

impl EasyTotp {
    fn new_totp(
        raw_secret: String,
        issuer: Option<String>,
        account_name: String,
    ) -> Result<TOTP, String> {
        let secret;
        let result_secret = Secret::Raw(raw_secret.as_bytes().to_vec()).to_bytes();

        if let Ok(okay_secret) = result_secret {
            secret = okay_secret;
        } else {
            return Err(String::from("Failed to parse secret key"));
        }

        let result = TOTP::new(Algorithm::SHA512, 6, 1, 30, secret, issuer, account_name);

        if let Ok(okay_result) = result {
            Ok(okay_result)
        } else {
            Err(String::from("Error creating new TOTP instance"))
        }
    }

    fn create_qr(
        raw_secret: String,
        issuer: Option<String>,
        account_name: String,
    ) -> Result<String, Box<dyn Error>> {
        let result = Self::new_totp(raw_secret, issuer, account_name)?.get_qr_base64();

        if let Ok(okay_result) = result {
            Ok(okay_result)
        } else {
            Err(Box::new(EasyTotpError::new("Error creating QR code data")))
        }
    }

    /// Creates a new PNG with a QR code
    ///
    /// BEWARE: PNG image contains secret!!
    pub fn create_qr_png(
        raw_secret: String,
        issuer: Option<String>,
        account_name: String,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
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

    /// Generates a TOTP token for authentication
    pub fn generate_token(
        raw_secret: String,
        issuer: Option<String>,
        account_name: String,
    ) -> Result<String, Box<dyn Error>> {
        Ok(Self::new_totp(raw_secret, issuer, account_name)?.generate_current()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image;
    use rqrr;
    use std::fs;
    use std::io::Write;

    #[test]
    fn test_qr_png() {
        let raw_secret = String::from("SUPERSecretSecretSecret");
        let issuer = Some(String::from("McCormick"));
        let account_name = String::from("test@test-email.com");
        let filename = "./test_images/qr_code.png";

        match EasyTotp::create_qr_png(raw_secret, issuer, account_name) {
            Ok(png_data) => {
                let mut file = fs::File::create(filename).unwrap();
                file.write_all(&png_data).unwrap();
                println!("QR code saved as 'qr_code.png'");
            }
            Err(e) => {
                panic!("Error creating QR code: {:?}", e);
            }
        }

        let img = image::open(filename).unwrap().to_luma8();
        // Prepare for detection
        let mut img = rqrr::PreparedImage::prepare(img);
        // Search for grids, without decoding
        let grids = img.detect_grids();
        assert_eq!(grids.len(), 1);
        // Decode the grid
        let (meta, content) = grids[0].decode().unwrap();
        assert_eq!(meta.ecc_level, 0);
        assert_eq!(
            content,
            "otpauth://totp/McCormick:test%40test-email.com?secret=KNKVARKSKNSWG4TFORJWKY3SMV2FGZLDOJSXI&algorithm=SHA512&issuer=McCormick"
        );

        // Delete file
        fs::remove_file(filename).unwrap();
    }
}
