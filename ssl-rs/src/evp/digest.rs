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
pub enum DigestType {
    MD5,
    SHA1,
    SHA224,
    #[default]
    SHA256,
    SHA384,
    SHA512,
    RIPEMD160,
    Whirlpool,
    SHA3256,
    BLAKE2b512,
}

impl DigestType {
    unsafe fn to_md(&self) -> *const EVP_MD {
        match self {
            DigestType::MD5 => EVP_md5(),
            DigestType::SHA1 => EVP_sha1(),
            DigestType::SHA224 => EVP_sha224(),
            DigestType::SHA256 => EVP_sha256(),
            DigestType::SHA384 => EVP_sha384(),
            DigestType::SHA512 => EVP_sha512(),
            DigestType::RIPEMD160 => EVP_ripemd160(),
            DigestType::Whirlpool => EVP_whirlpool(),
            DigestType::SHA3256 => EVP_sha3_256(),
            DigestType::BLAKE2b512 => EVP_blake2b512(),
        }
    }
}

pub fn hash(message: &[u8], digest: DigestType) -> Result<Vec<u8>, ErrorStack> {
    unsafe {
        let mdctx = EvpMdCtx::default();
        crate::check_code(EVP_DigestInit_ex(
            mdctx.as_ptr(),
            digest.to_md(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_hash_function() {
        let message = b"hello world";
        let expected_hash =
            hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        let result = hash(message.as_ref(), DigestType::SHA256).expect("Hash computation failed");

        assert_eq!(
            result, expected_hash,
            "The hash does not match the expected value"
        );
    }
}
