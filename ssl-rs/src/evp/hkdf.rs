use foreign_types::ForeignType;

use super::{digest::DigestAlgorithm, evp_ctx::EvpCtx, EvpId};
use crate::{error::ErrorStack, ssl::*};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hkdf(Vec<u8>);

impl Hkdf {
    pub fn derive_key(salt: &[u8], key: &[u8], info: Option<&[u8]>) -> Result<Self, ErrorStack> {
        unsafe {
            let hkdf_ctx = EvpCtx::from(EvpId::Hkdf);
            crate::check_code(EVP_PKEY_derive_init(hkdf_ctx.as_ptr()))?;
            crate::check_code(EVP_PKEY_CTX_set_hkdf_md(
                hkdf_ctx.as_ptr(),
                DigestAlgorithm::SHA256.to_md(),
            ))?;
            crate::check_code(EVP_PKEY_CTX_set1_hkdf_salt(
                hkdf_ctx.as_ptr(),
                salt.as_ptr(),
                salt.len() as i32,
            ))?;
            crate::check_code(EVP_PKEY_CTX_set1_hkdf_key(
                hkdf_ctx.as_ptr(),
                key.as_ptr(),
                key.len() as i32,
            ))?;

            if let Some(info) = info {
                crate::check_code(EVP_PKEY_CTX_add1_hkdf_info(
                    hkdf_ctx.as_ptr(),
                    info.as_ptr(),
                    info.len() as i32,
                ))?;
            }

            let mut hkdf_key_len = 32;
            let mut hkdf_key = Vec::with_capacity(hkdf_key_len);
            crate::check_code(EVP_PKEY_derive(
                hkdf_ctx.as_ptr(),
                hkdf_key.as_mut_ptr(),
                &mut hkdf_key_len,
            ))?;
            hkdf_key.set_len(hkdf_key_len);

            Ok(Self(hkdf_key))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_function() {
        // Define the test inputs based on RFC 5869 Test Case 1
        let salt: &[u8] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        
        let ikm: Vec<u8> = vec![0x0b; 22]; // IKM = 0x0b repeated 22 times
        
        let info: &[u8] = &[
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
            0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
        ];
        
        // Expected OKM (32 bytes)
        let expected_okm: Vec<u8> = vec![
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
            0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        ];

        // Perform key derivation
        let derived = Hkdf::derive_key(salt, &ikm, Some(info))
            .expect("Key derivation failed");

        // Assert that the derived key matches the expected OKM
        assert_eq!(derived.0, expected_okm, "Derived key does not match the expected OKM");
    }
}