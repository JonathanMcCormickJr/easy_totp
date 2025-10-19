#![deny(missing_docs)]
#![deny(unsafe_code)]

//! `easy_totp` is a crate designed to make it easy to integrate TOTP into your Rust apps.
//!
//! **BEWARE: handle secrets with caution**
//!
//! ## Creating a QR code for TOTP setup
//!
//! ```rust
//! use easy_totp::EasyTotp;
//!
//! let raw_secret = String::from("SUPERSecretSecretSecret");
//! let issuer = Some(String::from("McCormick"));
//! let account_name = String::from("test@test-email.com");
//!
//! let my_qr_code = EasyTotp::create_qr_png(raw_secret, issuer, account_name);
//! ```
//!
//! ## Saving that QR code to a file
//!
//! ```rust
//! use easy_totp::EasyTotp;
//! use std::fs;
//! use std::io::Write;
//!
//! let raw_secret = String::from("SUPERSecretSecretSecret");
//! let issuer = Some(String::from("McCormick"));
//! let account_name = String::from("test@test-email.com");
//! let filename = "./test_images/qr_code.png";
//!
//! let my_qr_code = EasyTotp::create_qr_png(raw_secret, issuer, account_name);
//!
//! match my_qr_code {
//!     Ok(png_data) => {
//!         let mut file = fs::File::create(filename).unwrap();
//!         file.write_all(&png_data).unwrap();
//!         println!("QR code saved as 'qr_code.png'");
//!     }
//!     Err(e) => {
//!         panic!("Error creating QR code: {:?}", e);
//!     }
//! }
//! ```
//!
//! ## Generating TOTP codes for authentication
//!
//! ```rust
//! use easy_totp::EasyTotp;
//!
//! let raw_secret = String::from("SUPERSecretSecretSecret");
//! let issuer = Some(String::from("McCormick"));
//! let account_name = String::from("test@test-email.com");
//!
//! let token = EasyTotp::generate_token(raw_secret, issuer, account_name).unwrap();
//! ```
//!

use totp_rs::{Algorithm, Secret, TOTP};

use base64::decode;
use image::{ImageBuffer, Luma};
use std::error::Error;
use std::fmt;
use std::io::{Cursor, stdout, Write};

#[derive(Debug)]
struct EasyTotpError(String);

impl fmt::Display for EasyTotpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EasyTotp encountered an error: {}", self.0)
    }
}

impl Error for EasyTotpError {}

impl EasyTotpError {
    fn new(message: &str) -> Self {
        EasyTotpError(message.to_string())
    }
}

/// `EasyTotp` is a unit-struct to keep track of externally-implemented code.
pub struct EasyTotp;

impl EasyTotp {
    fn new_totp(
        raw_secret: String,
        issuer: Option<String>,
        account_name: String,
    ) -> Result<TOTP, EasyTotpError> {
        let secret;
        let result_secret = Secret::Raw(raw_secret.as_bytes().to_vec()).to_bytes();

        if let Ok(okay_secret) = result_secret {
            secret = okay_secret;
        } else {
            return Err(EasyTotpError::new("Failed to parse secret key"));
        }

        let result = TOTP::new(Algorithm::SHA512, 6, 1, 30, secret, issuer, account_name);

        if let Ok(okay_result) = result {
            Ok(okay_result)
        } else {
            Err(EasyTotpError::new("Error creating new TOTP instance"))
        }
    }

    fn create_qr(
        raw_secret: String,
        issuer: Option<String>,
        account_name: String,
    ) -> Result<String, EasyTotpError> {
        let result = Self::new_totp(raw_secret, issuer, account_name)?.get_qr_base64();

        if let Ok(okay_result) = result {
            Ok(okay_result)
        } else {
            Err(EasyTotpError::new("Error creating QR code data"))
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

    /// Render the QR code in the terminal
    /// 
    /// BEWARE: terminal will display secret!!
    pub fn render_qr_terminal(
        raw_secret: String,
        issuer: Option<String>,
        account_name: String,
    ) -> Result<(), Box<dyn Error>> {
        let decoded_data = decode(Self::create_qr(raw_secret, issuer, account_name)?)?;

        let img = image::load_from_memory(&decoded_data)?.to_luma8();

        let width = img.width();
        let height = img.height();


        // Determine scaling factor to fit terminal
        let terminal_width = 80; // Typical terminal width in characters
        let scale_x = width / terminal_width;
        let scale_y = scale_x * 2; // Height is doubled for character aspect ratio

        for y in (0..height).step_by(scale_y as usize) {
            for x in (0..width).step_by(scale_x as usize) {
                // Sample the block of pixels and determine overall darkness
                let block_darkness = (0..scale_x).flat_map(|dx| 
                    (0..scale_y).map({
                        let img_val = img.clone();
                        move |dy| {
                            let px = (x + dx).min(width - 1);
                            let py = (y + dy).min(height - 1);
                            img_val.get_pixel(px, py)[0]
                        }
                    }
                    )
                ).filter(|&p| p < 128).count();
    
                let total_pixels = (scale_x * scale_y) as usize;
                let symbol = match block_darkness as f32 / total_pixels as f32 {
                    d if d > 0.7 => '█', // Very dark
                    d if d > 0.4 => '▓', // Medium-dark
                    d if d > 0.2 => '▒', // Light
                    _ => ' ',            // Very light
                };

                print!("{}", symbol);
            }
            println!();
        }

        stdout().flush()?;

        Ok(())
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
    use std::{thread, time};

    #[test]
    fn test_qr_png() {
        let raw_secret = String::from("SUPERSecretSecretSecret");
        let issuer = Some(String::from("McCormick"));
        let account_name = String::from("test@test-email.com");
        let filename = "./test_images/qr_code.png";

        let my_qr_code = EasyTotp::create_qr_png(raw_secret, issuer, account_name);

        match my_qr_code {
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

    #[test]
    fn test_qr_terminal() {
        let raw_secret = String::from("SUPERSecretSecretSecret");
        let issuer = Some(String::from("McCormick"));
        let account_name = String::from("Account_name");
        match EasyTotp::render_qr_terminal(raw_secret, issuer, account_name) {
            Ok(_) => println!("QR code rendered in terminal successfully."),
            Err(e) => panic!("Error rendering QR code in terminal: {:?}", e),
        }
    }

    #[test]
    fn test_code_generation() {
        let raw_secret = String::from("SUPERSecretSecretSecret");
        let issuer = Some(String::from("McCormick"));
        let account_name = String::from("test@test-email.com");

        let token1 =
            EasyTotp::generate_token(raw_secret.clone(), issuer.clone(), account_name.clone())
                .unwrap();
        let token2 =
            EasyTotp::generate_token(raw_secret.clone(), issuer.clone(), account_name.clone())
                .unwrap();

        assert_eq!(token1, token2);

        thread::sleep(time::Duration::from_secs(30));

        let token3 =
            EasyTotp::generate_token(raw_secret.clone(), issuer.clone(), account_name.clone())
                .unwrap();
        assert_ne!(token1, token3);

        assert_eq!((6, 6, 6), (token1.len(), token2.len(), token3.len()));

        assert_eq!(
            (true, true, true),
            (
                token1.parse::<u32>().is_ok(),
                token2.parse::<u32>().is_ok(),
                token3.parse::<u32>().is_ok(),
            )
        );
    }
}
