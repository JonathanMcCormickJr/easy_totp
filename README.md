# easy_totp

TOTP in Rust, but with just a few simple functions to call. 

**BEWARE: handle secrets with caution**

## Creating a QR code for TOTP setup

```rust 
use easy_totp::EasyTotp;

let raw_secret = String::from("SUPERSecretSecretSecret");
let issuer = Some(String::from("McCormick"));
let account_name = String::from("test@test-email.com");

let my_qr_code = EasyTotp::create_qr_png(raw_secret, issuer, account_name);
```

## Saving that QR code to a file

```rust
use easy_totp::EasyTotp;
use std::fs;
use std::io::Write;

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
```

## Generating TOTP codes for authentication

```rust
use easy_totp::EasyTotp;

let raw_secret = String::from("SUPERSecretSecretSecret");
let issuer = Some(String::from("McCormick"));
let account_name = String::from("test@test-email.com");

let token = EasyTotp::generate_token(raw_secret, issuer, account_name).unwrap();
```