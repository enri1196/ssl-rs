use std::ffi::c_char;

use foreign_types::{foreign_type, ForeignType};

use crate::{error::ErrorStack, ossl_param::OsslParamBld, ssl::*};

foreign_type! {
    pub unsafe type EvpMac {
        type CType = EVP_MAC;
        fn drop = EVP_MAC_free;
    }
}

#[derive(Debug, Clone, Copy)]
enum MacAlgorithm {
    CMAC,
}

impl From<MacAlgorithm> for &'static str {
    fn from(value: MacAlgorithm) -> Self {
        match value {
            MacAlgorithm::CMAC => "CMAC\0",
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
                std::ptr::null()
            ));
            EvpMacCtx::from_ptr(EVP_MAC_CTX_new(evp_mac.as_ptr()))
        }
    }
}

impl EvpMac {
    pub fn compute_cmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let ctx = EvpMacCtx::from(MacAlgorithm::CMAC);

            let params = OsslParamBld::new()
                .push_str("cipher\0", "AES-128-CBC\0")
                .build();

            EVP_MAC_init(ctx.as_ptr(), key.as_ptr(), key.len(), params.as_ptr());

            EVP_MAC_update(ctx.as_ptr(), data.as_ptr(), data.len());

            let mut cmac_value = Vec::with_capacity(EVP_MAX_MD_SIZE as usize);
            let mut cmac_len: usize = 0;
            EVP_MAC_final(ctx.as_ptr(), cmac_value.as_mut_ptr(), &mut cmac_len, EVP_MAX_MD_SIZE as usize);
            cmac_value.set_len(cmac_len);

            Ok(cmac_value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_cmac() {
        // Define the key, data, and expected CMAC as byte arrays
        let key: Vec<u8> = vec![
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];

        let data: Vec<u8> = vec![
            0x6b, 0xc1, 0xbe, 0xe2,
            0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11,
            0x73, 0x93, 0x17, 0x2a,
        ];

        let expected_cmac: Vec<u8> = vec![
            0x07, 0x0a, 0x16, 0xb4,
            0x6b, 0x4d, 0x41, 0x44,
            0xf7, 0x9b, 0xdd, 0x9d,
            0xd0, 0x4a, 0x28, 0x7c,
        ];

        // Compute the CMAC using the provided function
        let cmac_result = EvpMac::compute_cmac(&key, &data)
            .expect("CMAC computation failed");

        // Verify that the computed CMAC matches the expected value
        assert_eq!(
            cmac_result, expected_cmac,
            "Computed CMAC does not match the expected value"
        );
    }
}
