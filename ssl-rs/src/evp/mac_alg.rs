use std::ffi::c_char;

use foreign_types::{foreign_type, ForeignType};

use crate::{error::ErrorStack, ossl_param::OsslParamBld, ssl::*};

use super::{cipher::Cipher, digest::DigestAlgorithm};

foreign_type! {
    pub unsafe type EvpMac {
        type CType = EVP_MAC;
        fn drop = EVP_MAC_free;
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(unused)]
enum MacAlgorithm {
    CMAC,
    HMAC,
    POLY1305,
    GMAC,
    KMAC128,
    KMAC256,
    BLAKE2BMAC,
    BLAKE2SMAC,
    // PMAC,
    // UMAC,
    // VMAC,
}

impl From<MacAlgorithm> for &'static str {
    fn from(value: MacAlgorithm) -> Self {
        value.as_str()
    }
}

impl MacAlgorithm {
    pub(crate) const fn as_str(&self) -> &'static str {
        // SAFETY: all the Cstrings are compile time constants known to be safe
        unsafe { self.inner_as_str() }
    }

    const unsafe fn inner_as_str(&self) -> &'static str {
        match self {
            Self::CMAC => std::str::from_utf8_unchecked(SN_cmac.to_bytes()),
            Self::HMAC => std::str::from_utf8_unchecked(SN_hmac.to_bytes()),
            Self::POLY1305 => std::str::from_utf8_unchecked(SN_poly1305.to_bytes()),
            Self::GMAC => std::str::from_utf8_unchecked(SN_gmac.to_bytes()),
            Self::KMAC128 => std::str::from_utf8_unchecked(SN_kmac128.to_bytes()),
            Self::KMAC256 => std::str::from_utf8_unchecked(SN_kmac256.to_bytes()),
            Self::BLAKE2BMAC => std::str::from_utf8_unchecked(SN_blake2bmac.to_bytes()),
            Self::BLAKE2SMAC => std::str::from_utf8_unchecked(SN_blake2smac.to_bytes()),
            // Self::PMAC => std::str::from_utf8_unchecked(SN_cmac.to_bytes()),
            // Self::UMAC => std::str::from_utf8_unchecked(SN_cmac.to_bytes()),
            // Self::VMAC => std::str::from_utf8_unchecked(SN_cmac.to_bytes()),
        }
    }
}

foreign_type! {
    pub unsafe type EvpMacCtx {
        type CType = EVP_MAC_CTX;
        fn drop = EVP_MAC_CTX_free;
    }
}

impl From<MacAlgorithm> for EvpMacCtx {
    fn from(value: MacAlgorithm) -> Self {
        unsafe {
            let mac_name: &str = value.into();
            let evp_mac = EvpMac::from_ptr(EVP_MAC_fetch(
                std::ptr::null_mut(),
                mac_name.as_ptr() as *const c_char,
                std::ptr::null(),
            ));
            EvpMacCtx::from_ptr(EVP_MAC_CTX_new(evp_mac.as_ptr()))
        }
    }
}

impl EvpMac {
    pub fn compute_cmac(key: &[u8], data: &[u8], cipher: Cipher) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let ctx = EvpMacCtx::from(MacAlgorithm::CMAC);

            let params = OsslParamBld::new()
                .push_str("cipher\0", cipher.as_str())
                .build();

            EVP_MAC_init(ctx.as_ptr(), key.as_ptr(), key.len(), params.as_ptr());

            EVP_MAC_update(ctx.as_ptr(), data.as_ptr(), data.len());

            let mut cmac_value = Vec::with_capacity(EVP_MAX_MD_SIZE as usize);
            let mut cmac_len: usize = 0;
            EVP_MAC_final(
                ctx.as_ptr(),
                cmac_value.as_mut_ptr(),
                &mut cmac_len,
                EVP_MAX_MD_SIZE as usize,
            );
            cmac_value.set_len(cmac_len);

            Ok(cmac_value)
        }
    }

    pub fn compute_hmac(
        key: &[u8],
        data: &[u8],
        digest: DigestAlgorithm,
    ) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let ctx = EvpMacCtx::from(MacAlgorithm::HMAC);

            let params = OsslParamBld::new()
                .push_str("digest\0", digest.as_str())
                .build();

            EVP_MAC_init(ctx.as_ptr(), key.as_ptr(), key.len(), params.as_ptr());

            EVP_MAC_update(ctx.as_ptr(), data.as_ptr(), data.len());

            let mut cmac_value = Vec::with_capacity(EVP_MAX_MD_SIZE as usize);
            let mut cmac_len: usize = 0;
            EVP_MAC_final(
                ctx.as_ptr(),
                cmac_value.as_mut_ptr(),
                &mut cmac_len,
                EVP_MAX_MD_SIZE as usize,
            );
            cmac_value.set_len(cmac_len);

            Ok(cmac_value)
        }
    }

    pub fn compute_poly1305(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let ctx = EvpMacCtx::from(MacAlgorithm::POLY1305);

            if key.len() != 32 {
                return Err(ErrorStack::from("Poly1305 requires a 32-byte key"));
            }

            EVP_MAC_init(ctx.as_ptr(), key.as_ptr(), key.len(), std::ptr::null_mut());

            EVP_MAC_update(ctx.as_ptr(), data.as_ptr(), data.len());

            let mut mac_value = Vec::with_capacity(16); // Poly1305 produces a 16-byte MAC
            let mut mac_len: usize = 0;
            EVP_MAC_final(ctx.as_ptr(), mac_value.as_mut_ptr(), &mut mac_len, 16);
            mac_value.set_len(mac_len);

            Ok(mac_value)
        }
    }

    pub fn compute_gmac(
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let ctx = EvpMacCtx::from(MacAlgorithm::GMAC);

            let params = OsslParamBld::new()
                .push_str("cipher\0", Cipher::AES128GCM.as_str()) // GMAC typically uses AES in GCM mode
                .build();

            EVP_MAC_init(ctx.as_ptr(), key.as_ptr(), key.len(), params.as_ptr());

            if let Some(aad_data) = aad {
                EVP_MAC_update(ctx.as_ptr(), aad_data.as_ptr(), aad_data.len());
            }

            EVP_MAC_update(ctx.as_ptr(), data.as_ptr(), data.len());

            let mut mac_value = Vec::with_capacity(16); // GMAC typically produces a 16-byte MAC
            let mut mac_len: usize = 0;
            EVP_MAC_final(
                ctx.as_ptr(),
                mac_value.as_mut_ptr(),
                &mut mac_len,
                16,
            );
            mac_value.set_len(mac_len);

            Ok(mac_value)
        }
    }
    
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_cmac() {
        // Define key (16 bytes!!! since cipher is AES-128)
        let key: Vec<u8> = vec![
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];

        let data: Vec<u8> = vec![
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];

        let expected_cmac: Vec<u8> = vec![
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
            0x28, 0x7c,
        ];

        let cmac_result =
            EvpMac::compute_cmac(&key, &data, Cipher::AES128CBC).expect("CMAC computation failed");

        assert_eq!(
            cmac_result, expected_cmac,
            "Computed CMAC does not match the expected value"
        );
    }

    #[test]
    fn test_compute_hmac() {
        let key: Vec<u8> = vec![0x0b; 20];

        let data: Vec<u8> = b"Hi There".to_vec();

        let expected_hmac: Vec<u8> = vec![
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];

        let hmac_result = EvpMac::compute_hmac(&key, &data, DigestAlgorithm::SHA256)
            .expect("HMAC computation failed");

        assert_eq!(
            hmac_result, expected_hmac,
            "Computed HMAC does not match the expected value"
        );
    }

    #[test]
    fn test_compute_poly1305() {
        // Define key (32 bytes!!!)
        let key = b"mysupersecretkeyforpoly1305algor".as_ref();

        let data = b"Cryptographic Forum Research Group".as_ref();

        let expected_mac: Vec<u8> = vec![
            0x02, 0xC6, 0x82, 0xD9, 0x87, 0xD2,
            0x3C, 0xFF, 0x9D, 0x50, 0x60, 0xAC,
            0xBD, 0x3C, 0x36, 0x56,
        ];

        let mac_result = EvpMac::compute_poly1305(key, data).expect("Poly1305 computation failed");

        assert_eq!(
            mac_result, expected_mac,
            "Computed Poly1305 MAC does not match the expected value"
        );
    }

    #[test]
    fn test_compute_gmac() {
        let key: Vec<u8> = vec![
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        ];

        let data: Vec<u8> = b"GMAC data".to_vec();
        let aad: Vec<u8> = b"Additional Authenticated Data".to_vec();

        let gmac_result = EvpMac::compute_gmac(&key, &data, Some(&aad)).expect("GMAC computation failed");

        assert_eq!(
            gmac_result.len(), 16,
            "Computed GMAC does not match the expected value"
        );
    }
}
