#![deny(missing_docs)]
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]
#![warn(missing_copy_implementations)]
#![warn(missing_debug_implementations)]
#![warn(clippy::pedantic)]

//! `easy_totp` is a crate designed to make it easy to integrate TOTP into your Rust apps.
//!
//! **BEWARE: handle secrets with caution**
//!
//! ## Creating a QR code for TOTP setup
//!
//! ```rust
//! use easy_totp::EasyTotp;
//!
//! let issuer = Some(String::from("McCormick"));
//! let account_name = String::from("test@test-email.com");
//!
//! let et = EasyTotp::new(issuer, account_name).unwrap();
//!
//! let my_qr_code = et.create_qr_png();
//! ```
//!
//! ## Saving that QR code to a file
//!
//! ```rust
//! use easy_totp::EasyTotp;
//! use std::fs;
//! use std::io::Write;
//!
//! let issuer = Some(String::from("McCormick"));
//! let account_name = String::from("test@test-email.com");
//! let filename = "./test_images/qr_code.png";
//!
//! let et = EasyTotp::new(issuer, account_name).unwrap();
//!
//! let my_qr_code = et.create_qr_png();
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
//! let issuer = Some(String::from("McCormick"));
//! let account_name = String::from("test@test-email.com");
//!
//! let et = EasyTotp::new(issuer, account_name).unwrap();
//!
//! let token = et.generate_token().unwrap();
//! ```
//!

use totp_rs::{Algorithm, Secret, TOTP};

use base64::{Engine as _, engine::general_purpose};
use rand::{TryRngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{self};
use std::io::{Cursor, Write, stdout};

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
enum TerminalQRSize {
    #[default]
    Full = 0,
    #[allow(dead_code)]
    Mini = 1,
}

/// `QRColorMode` defines whether the QR code is rendered in direct or inverted colors
/// For light mode, use `Direct`; for dark mode, use `Inverted`. Some QR scanners may still be able to read either way.
#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum QRColorMode {
    /// Direct colors (black on white during light mode, vice versa for dark mode)
    Direct = 0,
    #[default]
    /// Inverted colors (white on black during light mode, vice versa for dark mode)
    Inverted = 1,
}

/// `EasyTotp` is a unit-struct to keep track of externally-implemented code.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EasyTotp {
    raw_secret: String,
    issuer: Option<String>,
    account_name: String,
}

impl EasyTotp {
    /// Creates a new `EasyTotp` instance with a randomly generated secret key
    ///
    /// ## Errors
    /// This function will return an error if the random number generator fails to generate bytes for the secret key.
    pub fn new(
        issuer: Option<String>,
        account_name: String,
    ) -> Result<Self, <OsRng as TryRngCore>::Error> {
        // Use OsRng to generate a random secret key
        let mut secret_bytes = [0u8; 20];
        OsRng.try_fill_bytes(&mut secret_bytes)?;
        let raw_secret = String::from_utf8_lossy(&secret_bytes).to_string();

        Ok(EasyTotp {
            raw_secret,
            issuer,
            account_name,
        })
    }

    /// Creates a new TOTP instance
    fn new_totp(self) -> Result<TOTP, EasyTotpError> {
        let secret;
        let result_secret = Secret::Raw(self.raw_secret.as_bytes().to_vec()).to_bytes();

        if let Ok(okay_secret) = result_secret {
            secret = okay_secret;
        } else {
            return Err(EasyTotpError::new("Failed to parse secret key"));
        }

        let result = TOTP::new(
            Algorithm::SHA512,
            6,
            1,
            30,
            secret,
            self.issuer,
            self.account_name,
        );

        if let Ok(okay_result) = result {
            Ok(okay_result)
        } else {
            Err(EasyTotpError::new("Error creating new TOTP instance"))
        }
    }

    fn create_qr(et: EasyTotp) -> Result<String, EasyTotpError> {
        let result = Self::new_totp(et)?.get_qr_base64();

        if let Ok(okay_result) = result {
            Ok(okay_result)
        } else {
            Err(EasyTotpError::new("Error creating QR code data"))
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn qr_text(
        size: TerminalQRSize,
        mode: QRColorMode,
        et: EasyTotp,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let mut lines = Vec::new();
        let decoded_data = general_purpose::STANDARD.decode(Self::create_qr(et)?)?;

        let img = image::load_from_memory(&decoded_data)?.to_luma8();

        let width = img.width();
        let height = img.height();

        // Determine scaling factor to fit terminal
        let terminal_width = 100; // Typical terminal width in characters
        let scale_x = width / terminal_width;
        let scale_y = scale_x * 2; // Height is doubled for character aspect ratio

        for y in (0..height).step_by(scale_y as usize) {
            let mut line = String::new();
            for x in (0..width).step_by(scale_x as usize) {
                // Sample the block of pixels and determine overall darkness
                let block_darkness = (0..scale_x)
                    .flat_map(|dx| {
                        (0..scale_y).map({
                            let img_val = img.clone();
                            move |dy| {
                                let px = (x + dx).min(width - 1);
                                let py = (y + dy).min(height - 1);
                                img_val.get_pixel(px, py)[0]
                            }
                        })
                    })
                    .filter(|&p| p < 128)
                    .count();

                let total_pixels = (scale_x * scale_y) as usize;
                let symbol = match block_darkness as f32 / total_pixels as f32 {
                    d if d > 0.7 => '█', // Very dark
                    d if d > 0.4 => '▓', // Medium-dark
                    d if d > 0.2 => '▒', // Light
                    _ => ' ',            // Very light
                };

                line.push(symbol);
            }
            lines.push(line);
        }
        lines.push(String::from(
            "Scan the above QR code with your authenticator app to set up TOTP.",
        ));
        lines.push(String::from(
            "BEWARE: this QR code contains your secret key! Handle with care.",
        ));
        lines.push(String::from("Useful tips: if scanning fails, try inverting the QR code colors by adjusting your terminal's background color or "));
        lines.push(String::from("using your mouse to select the entire QR code area. Also, ensure your terminal zoom is set to a level that allows "));
        lines.push(String::from(
            "the QR code to be completely visible onscreen.",
        ));

        stdout().flush()?;

        match mode {
            QRColorMode::Direct => {}
            QRColorMode::Inverted => {
                for line in &mut lines {
                    // Skip lines that contain alphanumeric text
                    if line.chars().any(|c| {
                        c.is_alphanumeric() || c == ':' || c == '.' || c == '@' || c == '!'
                    }) {
                        continue;
                    }

                    *line = line
                        .chars()
                        .map(|c| match c {
                            '█' => ' ',
                            '▓' => '░',
                            '▒' => '▓',
                            ' ' => '█',
                            _ => c,
                        })
                        .collect();
                }
            }
        }

        match size {
            TerminalQRSize::Full => Ok(lines),
            TerminalQRSize::Mini => {
                let mut mini_lines = Vec::new();

                for line in lines.chunks(2) {
                    let mut mini_line = String::new();
                    for (c1, c2) in line[0]
                        .chars()
                        .zip(line.get(1).unwrap_or(&String::new()).chars())
                    {
                        let mini_char = match (c1, c2) {
                            ('█' | '▓' | '▒', ' ') => '▀',
                            (' ', '█' | '▓' | '▒') => '▄',
                            ('█', '█') => '█',
                            ('▓', '▓') => '▓',
                            ('▒', '▒') => '▒',
                            _ => ' ',
                        };
                        mini_line.push(mini_char);
                    }
                    mini_lines.push(mini_line);
                }

                Ok(mini_lines)
            }
        }
    }

    /// Creates a new PNG with a QR code
    ///
    /// BEWARE: PNG image contains secret!!
    ///
    /// ## Creating a QR code for TOTP setup
    /// ```rust
    /// use easy_totp::EasyTotp;
    ///
    /// let issuer = Some(String::from("McCormick"));
    /// let account_name = String::from("test@test-email.com");
    /// let et = EasyTotp::new(issuer, account_name).unwrap();
    ///
    /// let my_qr_code = et.create_qr_png().unwrap();
    /// ```
    ///
    /// ## Errors
    /// This function will return an error if the QR code generation or image processing fails.
    pub fn create_qr_png(self) -> Result<Vec<u8>, Box<dyn Error>> {
        // Decode the base64 string
        let decoded_data = general_purpose::STANDARD.decode(Self::create_qr(self)?)?;

        // Create a dynamic image from the decoded data
        let image = image::load_from_memory(&decoded_data)?;

        // Write the image to a buffer as a PNG
        let mut buffer = Vec::new();
        let mut cursor = Cursor::new(&mut buffer);
        image.write_to(&mut cursor, image::ImageFormat::Png)?;

        Ok(buffer)
    }

    /// Print the QR code to the terminal
    ///
    /// BEWARE: terminal will display secret!!
    ///
    /// ```rust
    /// use easy_totp::{EasyTotp, QRColorMode};
    /// let issuer = Some(String::from("McCormick"));
    /// let account_name = String::from("test@test-email.com");
    /// let et = EasyTotp::new(issuer, account_name).unwrap();
    /// et.print_qr_to_teminal(QRColorMode::Inverted).unwrap();
    /// ```
    ///
    /// That will print out a QR code in the terminal that you can potentially scan with your authenticator app. Your mileage may vary.
    ///
    /// ### Example authenticator apps and whether they can scan from terminal output
    /// - ✔️ Aegis Authenticator (Android)
    /// - ✔️ Bitwarden Authenticator (Android)
    /// - ✔️ Proton Authenticator (Android)
    /// - ✔️ Google Authenticator (Android)
    ///
    /// ```text
    /// ██████████████████████████████████████████████████████████████████████████████████████████████████████████████████
    /// ██████████████████████████████████████████████████████████████████████████████████████████████████████████████████
    /// ██████████████████████████████████████████████████████████████████████████████████████████████████████████████████
    /// ██████████████████████████████████████████████████████████████████████████████████████████████████████████████████
    /// ████████              ████        ██      ██      ██████            ████  ██  ████  ████  ██              ████████
    /// ████████  ██████████  ████████        ██  ██      ██  ██  ██████  ██        ██  ██        ██  ██████████  ████████
    /// ████████  ██      ██  ██    ██████████████    ██  ██████  ████  ████████  ██  ████████    ██  ██      ██  ████████
    /// ████████  ██      ██  ██        ██        ████████      ██    ████      ████████    ██  ████  ██      ██  ████████
    /// ████████  ██      ██  ██  ██████    ██                        ██      ██  ████      ████████  ██      ██  ████████
    /// ████████  ██████████  ██  ████  ██  ████████████  ██  ██████    ██████████    ████    ██████  ██████████  ████████
    /// ████████              ██  ██  ██  ██  ██  ██  ██  ██  ██  ██  ██  ██  ██  ██  ██  ██  ██  ██              ████████
    /// ████████████████████████    ██    ██  ████  ██        ██████  ██████    ████    ████████  ████████████████████████
    /// ████████  ██          ████  ████  ██████    ████              ████████  ████████          ██          ████████████
    /// ████████  ████      ██    ██  ████  ████        ██  ██████  ████        ████████    ██████          ██████████████
    /// ████████████████████  ██    ██          ██████  ██      ██      ████  ████  ██    ██  ██    ██    ██      ████████
    /// ██████████    ██    ████        ██████  ██      ██  ██  ██  ████  ██████  ██████    ██  ██    ████████    ████████
    /// ████████  ██████      ████  ████  ██  ████      ██    ██      ████      ██        ████  ████    ██████  ██████████
    /// ██████████  ██████  ████      ████      ██    ████  ██      ██████      ██████  ██  ██████    ██  ██    ██████████
    /// ████████████████  ██      ██████    ████        ████████  ████████  ██          ██████  ██████████████    ████████
    /// ████████████████    ██  ████    ██      ██    ████  ████  ██  ██████    ██  ██    ██  ██  ██  ██  ████  ██████████
    /// ██████████████  ████  ████████████████    ████    ████    ████  ██    ██████████      ██    ██  ██  ██  ██████████
    /// ████████  ██  ██  ██████  ██████████████    ██  ████████    ████████    ██  ██    ████████    ██  ████  ██████████
    /// ████████████████        ████        ██████  ██      ██    ████  ██    ██████████  ██████  ████      ████  ████████
    /// ██████████    ██  ████  ██  ██  ██████    ██  ████████  ████████████        ████    ████          ████████████████
    /// ████████      ██████  ████        ██████  ██  ████    ██    ██████  ██  ████      ████    ████  ████  ██  ████████
    /// ████████████  ██    ██    ██  ██████  ████      ████  ██  ████████        ██████    ██  ██      ██  ██  ██████████
    /// ████████████              ██        ██      ██    ██          ██  ████      ████████  ██          ██████  ████████
    /// ████████████  ██  ██████    ██    ████  ████    ████  ██████  ████████████      ██  ████  ██████  ████    ████████
    /// ████████    ██    ██  ██    ██    ██  ██████  ██      ██  ██  ████  ██  ████        ████  ██  ██      ████████████
    /// ████████████      ██████  ██  ████  ██    ██████████  ██████          ██  ████      ████  ██████    ██████████████
    /// ██████████                ████        ██    ██████            ██        ██  ██    ██              ██      ████████
    /// ████████    ██████  ██  ██      ████  ██  ██    ██          ██        ██    ██████    ██  ██    ██████    ████████
    /// ████████████  ██            ██████  ██      ████████        ████████    ████████          ██  ██    ██    ████████
    /// ██████████  ██    ████        ██  ██        ██      ████  ████  ██    ██  ██████    ██  ██████  ████  ████████████
    /// ████████      ██  ██        ██    ██  ██  ██████  ██      ████████████████    ██  ████████        ████    ████████
    /// ████████  ██        ████████  ████████  ██████    ██████  ██    ██  ████████  ██          ████████████    ████████
    /// ████████  ████  ████  ████  ████  ██      ████    ██    ██  ████  ████          ████    ██████          ██████████
    /// ████████  ██      ████  ██████    ██  ██  ████  ████████            ████  ██  ████    ██████  ████  ██  ██████████
    /// ████████████  ██      ██      ████    ████████            ██████  ██        ██  ████████  ██  ██    ██    ████████
    /// ████████  ██    ██  ██            ████  ██  ██████  ██        ██  ██████    ██        ████  ██  ██████    ████████
    /// ████████  ██      ██  ████  ████    ██  ██      ██        ████  ██  ██  ████                ████          ████████
    /// ████████  ██        ██      ██      ██████  ██  ██          ████████      ████  ██  ██      ██████        ████████
    /// ██████████  ██████      ████████  ██    ██  ████  ██  ██  ██████    ██  ██    ██      ████    ████████    ████████
    /// ██████████      ████████  ██    ██  ██        ██                ████    ████  ████████████████    ████  ██████████
    /// ████████      ██████    ██████  ████████    ██                ████  ██  ██                            ████████████
    /// ████████████████████████  ██████  ████          ████  ██████  ██          ████████  ██    ██████  ██  ████████████
    /// ████████              ████        ██  ████  ██        ██  ██      ██  ██    ████      ██  ██  ██  ████    ████████
    /// ████████  ██████████  ██    ██████████████████████    ██████  ██  ████    ██    ████      ██████  ████    ████████
    /// ████████  ██      ██  ██      ████  ██  ██████  ████          ██████    ██  ██    ██  ██          ████  ██████████
    /// ████████  ██      ██  ██  ████  ████████    ██████  ██  ██                ██████    ██              ██  ██████████
    /// ████████  ██      ██  ██    ██    ██  ████      ██    ██  ██      ████              ██████  ██  ████      ████████
    /// ████████  ██████████  ████                  ██████████        ██████    ██  ██    ████████      ████████  ████████
    /// ████████              ██  ████    ██  ██  ██      ████    ████  ██    ██████████    ████      ████  ██    ████████
    /// ██████████████████████████████████████████████████████████████████████████████████████████████████████████████████
    /// ██████████████████████████████████████████████████████████████████████████████████████████████████████████████████
    /// ██████████████████████████████████████████████████████████████████████████████████████████████████████████████████
    /// ██████████████████████████████████████████████████████████████████████████████████████████████████████████████████
    /// Scan the above QR code with your authenticator app to set up TOTP.
    /// BEWARE: this QR code contains your secret key! Handle with care.
    /// Useful tips: if scanning fails, try inverting the QR code colors by adjusting your terminal's background color or
    /// using your mouse to select the entire QR code area. Also, ensure your terminal zoom is set to a level that allows
    /// the QR code to be completely visible onscreen.
    ///                                               
    /// ```
    /// ## Errors
    /// This function will return an error if the QR code generation or terminal rendering fails.
    pub fn print_qr_to_teminal(self, user_mode: QRColorMode) -> Result<(), Box<dyn Error>> {
        match user_mode {
            QRColorMode::Direct => Self::render_qr_terminal_full_direct(self),
            QRColorMode::Inverted => Self::render_qr_terminal_full_inverted(self),
        }
    }

    /// Render the QR code in the terminal
    ///
    /// BEWARE: terminal will display secret!!
    ///
    /// This function has been tested and has thus far received mixed results depending on the authenticator app used (Aegis seems to work well, whereas Proton Authenticator has trouble scanning from terminal). Your mileage may vary.
    fn render_qr_terminal_full_direct(self) -> Result<(), Box<dyn Error>> {
        for line in Self::qr_text(TerminalQRSize::Full, QRColorMode::Direct, self)? {
            println!("{line}");
        }
        Ok(())
    }

    #[allow(dead_code)]
    /// Render the mini QR code in the terminal
    ///
    /// BEWARE: terminal will display secret!!
    fn render_qr_terminal_mini_direct(self) -> Result<(), Box<dyn Error>> {
        for line in Self::qr_text(TerminalQRSize::Mini, QRColorMode::Direct, self)? {
            println!("{line}");
        }
        Ok(())
    }

    /// Render the QR code in the terminal, inverted colors
    ///
    /// BEWARE: terminal will display secret!!
    fn render_qr_terminal_full_inverted(self) -> Result<(), Box<dyn Error>> {
        for line in Self::qr_text(TerminalQRSize::Full, QRColorMode::Inverted, self)? {
            println!("{line}");
        }
        Ok(())
    }

    #[allow(dead_code)]
    /// Render the mini QR code in the terminal, inverted colors
    ///
    /// BEWARE: terminal will display secret!!
    fn render_qr_terminal_mini_inverted(self) -> Result<(), Box<dyn Error>> {
        for line in Self::qr_text(TerminalQRSize::Mini, QRColorMode::Inverted, self)? {
            println!("{line}");
        }
        Ok(())
    }

    /// Generates a TOTP token for authentication
    ///
    /// ## Errors
    /// This function will return an error if the TOTP generation fails.
    pub fn generate_token(self) -> Result<String, Box<dyn Error>> {
        Ok(Self::new_totp(self)?.generate_current()?)
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
        let issuer = Some(String::from("McCormick"));
        let account_name = String::from("test@test-email.com");
        let filename = "./test_images/qr_code.png";

        let et = EasyTotp::new(issuer, account_name).unwrap();

        let my_qr_code = EasyTotp::create_qr_png(et);

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
        assert!(content.starts_with("otpauth://totp/McCormick:test%40test-email.com?secret="));
        assert!(content.contains("&algorithm=SHA512&issuer=McCormick"));

        // Extract and validate the secret parameter
        let secret_start = content.find("secret=").unwrap() + 7;
        let secret_end = content.find("&algorithm=").unwrap();
        let secret = &content[secret_start..secret_end];

        // Ensure the secret is not empty and has reasonable length
        assert!(!secret.is_empty());
        assert!(
            secret.len() >= 20,
            "Secret should be at least 20 characters long"
        );

        // Verify the secret only contains valid base32 characters (A-Z, 2-7)
        assert!(
            secret
                .chars()
                .all(|c| c.is_ascii_uppercase() || "234567".contains(c)),
            "Secret should only contain valid base32 characters"
        );

        // Delete file
        fs::remove_file(filename).unwrap();
    }

    #[test]
    fn test_qr_terminal() {
        let raw_secret = String::from("SUPERSecretSecretSecret");
        let issuer = Some(String::from("McCormick"));
        let account_name = String::from("Account_name");

        let et = EasyTotp {
            raw_secret,
            issuer,
            account_name,
        };

        match EasyTotp::render_qr_terminal_full_direct(et) {
            Ok(_) => println!("QR code rendered in terminal successfully."),
            Err(e) => panic!("Error rendering QR code in terminal: {:?}", e),
        }
    }

    #[test]
    fn test_code_generation() {
        let raw_secret = String::from("SUPERSecretSecretSecret");
        let issuer = Some(String::from("McCormick"));
        let account_name = String::from("test@test-email.com");
        let et = EasyTotp {
            raw_secret: raw_secret.clone(),
            issuer: issuer.clone(),
            account_name: account_name.clone(),
        };

        let token1 = EasyTotp::generate_token(et.clone()).unwrap();
        let token2 = EasyTotp::generate_token(et.clone()).unwrap();

        assert_eq!(token1, token2);

        thread::sleep(time::Duration::from_secs(30));

        let token3 = EasyTotp::generate_token(et).unwrap();
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
