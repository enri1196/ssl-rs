use foreign_types::{foreign_type, ForeignType};

use crate::{error::ErrorStack, ssl::*};

foreign_type! {
    pub unsafe type EvpMdCtx: Sync + Send {
        type CType = EVP_MD_CTX;
        fn drop = EVP_MD_CTX_free;
        fn clone = EVP_MD_CTX_dup;
    }
}

impl Default for EvpMdCtx {
    fn default() -> Self {
        unsafe { Self::from_ptr(EVP_MD_CTX_new()) }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub enum DigestAlgorithm {
    MD5,
    SHA1,
    SHA224,
    #[default]
    SHA256,
    SHA384,
    SHA512,
    RIPEMD160,
    Whirlpool,
    SHA3224,
    SHA3256,
    SHA3384,
    SHA3512,
    BLAKE2b512,
}

impl From<DigestAlgorithm> for &'static str {
    fn from(value: DigestAlgorithm) -> Self {
        value.as_str()
    }
}

impl DigestAlgorithm {
    pub(crate) unsafe fn to_md(self) -> *const EVP_MD {
        match self {
            Self::MD5 => EVP_md5(),
            Self::SHA1 => EVP_sha1(),
            Self::SHA224 => EVP_sha224(),
            Self::SHA256 => EVP_sha256(),
            Self::SHA384 => EVP_sha384(),
            Self::SHA512 => EVP_sha512(),
            Self::RIPEMD160 => EVP_ripemd160(),
            Self::Whirlpool => EVP_whirlpool(),
            Self::SHA3224 => EVP_sha3_224(),
            Self::SHA3256 => EVP_sha3_256(),
            Self::SHA3384 => EVP_sha3_384(),
            Self::SHA3512 => EVP_sha3_512(),
            Self::BLAKE2b512 => EVP_blake2b512(),
        }
    }

    pub(crate) const fn as_str(&self) -> &'static str {
        // SAFETY: all the Cstrings are compile time constants known to be safe
        unsafe { self.inner_as_str() }
    }

    const unsafe fn inner_as_str(&self) -> &'static str {
        match self {
            Self::MD5 => std::str::from_utf8_unchecked(SN_md5.to_bytes()),
            Self::SHA1 => std::str::from_utf8_unchecked(SN_sha1.to_bytes()),
            Self::SHA224 => std::str::from_utf8_unchecked(SN_sha224.to_bytes()),
            Self::SHA256 => std::str::from_utf8_unchecked(SN_sha256.to_bytes()),
            Self::SHA384 => std::str::from_utf8_unchecked(SN_sha384.to_bytes()),
            Self::SHA512 => std::str::from_utf8_unchecked(SN_sha512.to_bytes()),
            Self::RIPEMD160 => std::str::from_utf8_unchecked(SN_ripemd160.to_bytes()),
            Self::Whirlpool => std::str::from_utf8_unchecked(SN_whirlpool.to_bytes()),
            Self::SHA3224 => std::str::from_utf8_unchecked(SN_sha3_224.to_bytes()),
            Self::SHA3256 => std::str::from_utf8_unchecked(SN_sha3_256.to_bytes()),
            Self::SHA3384 => std::str::from_utf8_unchecked(SN_sha3_384.to_bytes()),
            Self::SHA3512 => std::str::from_utf8_unchecked(SN_sha3_512.to_bytes()),
            Self::BLAKE2b512 => std::str::from_utf8_unchecked(SN_blake2b512.to_bytes()),
        }
    }

    pub fn hash(&self, message: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let digest_alg = self.to_md();
            let mdctx = EvpMdCtx::default();
            crate::check_code(EVP_DigestInit_ex(
                mdctx.as_ptr(),
                digest_alg,
                std::ptr::null_mut(),
            ))?;
            crate::check_code(EVP_DigestUpdate(
                mdctx.as_ptr(),
                message.as_ptr() as *const _,
                message.len(),
            ))?;
            let mut digest: Vec<u8> = Vec::with_capacity(EVP_MAX_MD_SIZE as usize);
            let mut digest_len: u32 = 0;
            crate::check_code(EVP_DigestFinal_ex(
                mdctx.as_ptr(),
                digest.as_mut_ptr(),
                &mut digest_len,
            ))?;
            digest.set_len(digest_len as usize);
            Ok(digest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_hash_function() {
        let message = b"hello world";
        let expected_hash =
            hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        let result = DigestAlgorithm::SHA256
            .hash(message.as_ref())
            .expect("Hash computation failed");

        assert_eq!(
            result, expected_hash,
            "The hash does not match the expected value"
        );
    }
}
