use cipher::{AlgorithmName, BlockBackend, BlockCipher, BlockSizeUser, ParBlocksSizeUser};

use crate::ssl::*;

#[derive(Debug, Clone, Copy)]
pub enum Cipher {
    AES128CBC,
    AES128ECB,
    AES128GCM,
    AES128CCM,
    AES192ECB,
    AES192CBC,
    AES192GCM,
    AES192CCM,
    AES256ECB,
    AES256CBC,
    AES256GCM,
    AES256CCM,
}

impl From<Cipher> for &'static str {
    fn from(value: Cipher) -> Self {
        value.as_str()
    }
}

impl Cipher {
    pub(crate) const fn as_str(&self) -> &'static str {
        // SAFETY: all the Cstrings are compile time constants known to be safe
        unsafe { self.inner_as_str() }
    }

    const unsafe fn inner_as_str(&self) -> &'static str {
        match self {
            Self::AES128CBC => std::str::from_utf8_unchecked(SN_aes_128_cbc.to_bytes()),
            Self::AES128ECB => std::str::from_utf8_unchecked(SN_aes_128_ecb.to_bytes()),
            Self::AES128GCM => std::str::from_utf8_unchecked(SN_aes_128_gcm.to_bytes()),
            Self::AES128CCM => std::str::from_utf8_unchecked(SN_aes_128_ccm.to_bytes()),
            Self::AES192ECB => std::str::from_utf8_unchecked(SN_aes_192_ecb.to_bytes()),
            Self::AES192CBC => std::str::from_utf8_unchecked(SN_aes_192_cbc.to_bytes()),
            Self::AES192GCM => std::str::from_utf8_unchecked(SN_aes_192_gcm.to_bytes()),
            Self::AES192CCM => std::str::from_utf8_unchecked(SN_aes_192_ccm.to_bytes()),
            Self::AES256ECB => std::str::from_utf8_unchecked(SN_aes_256_ecb.to_bytes()),
            Self::AES256CBC => std::str::from_utf8_unchecked(SN_aes_256_cbc.to_bytes()),
            Self::AES256GCM => std::str::from_utf8_unchecked(SN_aes_256_gcm.to_bytes()),
            Self::AES256CCM => std::str::from_utf8_unchecked(SN_aes_256_ccm.to_bytes()),
        }
    }
}
