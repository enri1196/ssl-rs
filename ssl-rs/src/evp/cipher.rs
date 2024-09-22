use crate::ssl::*;

#[derive(Debug, Clone, Copy)]
pub enum Cipher {
    AES128CBC,
    AES128ECB,
    AES128OFB,
}

impl From<Cipher> for &'static str {
    fn from(value: Cipher) -> Self {
        value.as_str()
    }
}

impl Cipher {
    // SAFETY: all the Cstrings are compile time constants known to be safe
    pub(crate) const fn as_str(&self) -> &'static str {
        unsafe { self.inner_as_str() }
    }

    const unsafe fn inner_as_str(&self) -> &'static str {
        match self {
            Self::AES128CBC => std::str::from_utf8_unchecked(SN_aes_128_cbc.to_bytes()),
            Self::AES128ECB => std::str::from_utf8_unchecked(SN_aes_128_ecb.to_bytes()),
            Self::AES128OFB => std::str::from_utf8_unchecked(SN_aes_128_ofb128.to_bytes()),
        }
    }
}
