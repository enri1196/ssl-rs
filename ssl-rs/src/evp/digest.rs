use std::marker::PhantomData;
use std::ptr;
use foreign_types::{foreign_type, ForeignType};
use generic_array::{ArrayLength, GenericArray};
use typenum::{U16, U20, U28, U32, U48, U64};
use digest::{Digest, Output, OutputSizeUser};
use crate::ssl::*;

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

pub trait MessageDigestTrait: Clone + Default {
    type OutputSize: ArrayLength<u8> + 'static;
    const OUTPUT_SIZE: usize;

    unsafe fn to_md() -> *const EVP_MD;
    fn as_str() -> &'static str;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MD5;
#[derive(Debug, Default, Clone, Copy)]
pub struct SHA1;
#[derive(Debug, Default, Clone, Copy)]
pub struct SHA224;
#[derive(Debug, Default, Clone, Copy)]
pub struct SHA256;
#[derive(Debug, Default, Clone, Copy)]
pub struct SHA384;
#[derive(Debug, Default, Clone, Copy)]
pub struct SHA512;

impl MessageDigestTrait for MD5 {
    type OutputSize = U16; // 16 bytes
    const OUTPUT_SIZE: usize = 16;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_md5()
    }

    fn as_str() -> &'static str {
        "md5"
    }
}

impl MessageDigestTrait for SHA1 {
    type OutputSize = U20; // 20 bytes
    const OUTPUT_SIZE: usize = 20;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha1()
    }

    fn as_str() -> &'static str {
        "sha1"
    }
}

impl MessageDigestTrait for SHA224 {
    type OutputSize = U28; // 28 bytes
    const OUTPUT_SIZE: usize = 28;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha224()
    }

    fn as_str() -> &'static str {
        "sha224"
    }
}

impl MessageDigestTrait for SHA256 {
    type OutputSize = U32; // 32 bytes
    const OUTPUT_SIZE: usize = 32;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha256()
    }

    fn as_str() -> &'static str {
        "sha256"
    }
}

impl MessageDigestTrait for SHA384 {
    type OutputSize = U48; // 48 bytes
    const OUTPUT_SIZE: usize = 48;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha384()
    }

    fn as_str() -> &'static str {
        "sha384"
    }
}

impl MessageDigestTrait for SHA512 {
    type OutputSize = U64; // 64 bytes
    const OUTPUT_SIZE: usize = 64;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha512()
    }

    fn as_str() -> &'static str {
        "sha512"
    }
}

#[derive(Clone)]
pub struct DigestAlgorithm<MD: MessageDigestTrait + Clone> {
    md: PhantomData<MD>,
    ctx: EvpMdCtx,
}

// Implement OutputSizeUser for DigestAlgorithm
impl<MD: MessageDigestTrait> OutputSizeUser for DigestAlgorithm<MD> {
    type OutputSize = MD::OutputSize;
}

// Implement the Digest trait
impl<MD: MessageDigestTrait> Digest for DigestAlgorithm<MD> {
    fn new() -> Self {
        unsafe {
            let ctx = EvpMdCtx::default();
            crate::check_code(EVP_DigestInit_ex(ctx.as_ptr(), MD::to_md(), ptr::null_mut()))
                .expect("Failed to initialize digest context");
            Self {
                md: PhantomData,
                ctx,
            }
        }
    }

    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        unsafe {
            crate::check_code(EVP_DigestUpdate(
                self.ctx.as_ptr(),
                data.as_ref().as_ptr() as *const _,
                data.as_ref().len(),
            ))
            .expect("Data hash update failed");
        }
    }

    fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        self.update(data);
        self
    }

    fn finalize(self) -> Output<Self> {
        unsafe {
            let mut digest = GenericArray::<u8, MD::OutputSize>::default();
            let mut digest_len: u32 = 0;
            crate::check_code(EVP_DigestFinal_ex(
                self.ctx.as_ptr(),
                digest.as_mut_ptr(),
                &mut digest_len,
            ))
            .expect("Data hash finalize failed");
            digest
        }
    }

    fn finalize_into(self, out: &mut Output<Self>) {
        unsafe {
            let mut digest_len: u32 = 0;
            crate::check_code(EVP_DigestFinal_ex(
                self.ctx.as_ptr(),
                out.as_mut_ptr(),
                &mut digest_len,
            ))
            .expect("Data hash finalize failed");
        }
    }

    fn finalize_reset(&mut self) -> Output<Self>
    where
        Self: digest::FixedOutputReset,
    {
        let result = self.clone().finalize();
        self.reset();
        result
    }

    fn finalize_into_reset(&mut self, out: &mut Output<Self>)
    where
        Self: digest::FixedOutputReset,
    {
        self.clone().finalize_into(out);
        self.reset();
    }

    fn reset(&mut self)
    where
        Self: digest::Reset,
    {
        unsafe {
            crate::check_code(EVP_DigestInit_ex(self.ctx.as_ptr(), MD::to_md(), ptr::null_mut()))
                .expect("Failed to reset digest context");
        }
    }

    fn output_size() -> usize {
        MD::OUTPUT_SIZE
    }

    fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl<MD: MessageDigestTrait> Default for DigestAlgorithm<MD> {
    fn default() -> Self {
        Self::new()
    }
}

impl<MD: MessageDigestTrait> std::fmt::Debug for DigestAlgorithm<MD> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DigestAlgorithm<{}>", MD::as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_sha256_hash() {
        let message = b"hello world";
        let expected_hash =
            hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        let result = DigestAlgorithm::<SHA256>::digest(message);

        assert_eq!(
            result.as_slice(),
            &expected_hash[..],
            "The hash does not match the expected value"
        );
    }
}
