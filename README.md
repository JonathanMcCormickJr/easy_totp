# easy_totp

TOTP in Rust, but with just a few simple functions to call. 

**BEWARE: handle secrets with caution**

This library is designed to make it easy to generate and manage TOTP secrets and codes. However, it is crucial to handle these secrets with care. Exposing your TOTP secrets can compromise the security of your accounts. Always ensure that your secrets are stored securely and are not shared or logged inappropriately.