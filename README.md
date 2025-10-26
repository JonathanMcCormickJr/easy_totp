# easy_totp

TOTP in Rust. Made easy. 

A lightweight library for generating and verifying Time‑Based One‑Time Passwords (TOTP) in Rust.

## Warnings
### Handle secrets with caution
It is crucial to handle these secrets with care. Exposing your TOTP secrets can compromise the security of your accounts. Always ensure that your secrets are stored securely and are not shared or logged inappropriately. Remember, if you use the QR code for onboarding, anyone with access to that QR code can generate valid TOTP codes for your account.

### Never send TOTP codes from the server to the client. 
It's okay to send a code from the client to the server for verification, but never the other way around.

### Consider rate limiting
To enhance security, consider implementing rate limiting on TOTP verification attempts. This can help prevent brute-force attacks.

## Features
- Create TOTP instances with random secret keys.
- Create TOTP onboarding QR codes.
    - PNG format.
    - Terminal display.
- Generate/verify TOTP codes.

## Documentation
The documentation for `easy_totp` can be found at [docs.rs/easy_totp](https://docs.rs/easy_totp).

## Contributing
Contributions are welcome! Please open an issue or submit a pull request on [GitHub](https://github.com/JonathanMcCormickJr/easy_totp).

By contributing to this project, you agree to have your contributions licensed under the project's overall license: MIT.