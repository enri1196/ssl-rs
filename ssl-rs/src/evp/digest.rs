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


impl MessageDigestTrait for MD5 {
    type OutputSize = U16; // 16 bytes
    const OUTPUT_SIZE: usize = 16;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_md5()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_md5.to_bytes())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SHA1;

impl MessageDigestTrait for SHA1 {
    type OutputSize = U20; // 20 bytes
    const OUTPUT_SIZE: usize = 20;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha1()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_sha1.to_bytes())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SHA224;

impl MessageDigestTrait for SHA224 {
    type OutputSize = U28; // 28 bytes
    const OUTPUT_SIZE: usize = 28;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha224()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_sha224.to_bytes())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SHA256;

impl MessageDigestTrait for SHA256 {
    type OutputSize = U32; // 32 bytes
    const OUTPUT_SIZE: usize = 32;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha256()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_sha256.to_bytes())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SHA384;

impl MessageDigestTrait for SHA384 {
    type OutputSize = U48; // 48 bytes
    const OUTPUT_SIZE: usize = 48;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha384()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_sha384.to_bytes())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SHA512;

impl MessageDigestTrait for SHA512 {
    type OutputSize = U64; // 64 bytes
    const OUTPUT_SIZE: usize = 64;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha512()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_sha512.to_bytes())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RIPEMD160;

impl MessageDigestTrait for RIPEMD160 {
    type OutputSize = U20; // 20 bytes
    const OUTPUT_SIZE: usize = 20;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_ripemd160()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_ripemd160.to_bytes())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Whirlpool;

impl MessageDigestTrait for Whirlpool {
    type OutputSize = U64; // 64 bytes
    const OUTPUT_SIZE: usize = 64;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_whirlpool()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_whirlpool.to_bytes())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SHA3_224;

impl MessageDigestTrait for SHA3_224 {
    type OutputSize = U28; // 28 bytes
    const OUTPUT_SIZE: usize = 28;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha3_224()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_sha3_224.to_bytes())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SHA3_256;

impl MessageDigestTrait for SHA3_256 {
    type OutputSize = U32; // 32 bytes
    const OUTPUT_SIZE: usize = 32;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha3_256()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_sha3_256.to_bytes())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SHA3_384;

impl MessageDigestTrait for SHA3_384 {
    type OutputSize = U48; // 48 bytes
    const OUTPUT_SIZE: usize = 48;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha3_384()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_sha3_384.to_bytes())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SHA3_512;

impl MessageDigestTrait for SHA3_512 {
    type OutputSize = U64; // 64 bytes
    const OUTPUT_SIZE: usize = 64;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_sha3_512()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_sha3_512.to_bytes())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct BLAKE2b512;

impl MessageDigestTrait for BLAKE2b512 {
    type OutputSize = U64; // 64 bytes
    const OUTPUT_SIZE: usize = 64;

    unsafe fn to_md() -> *const EVP_MD {
        EVP_blake2b512()
    }

    fn as_str() -> &'static str {
        unsafe {
            std::str::from_utf8_unchecked(SN_blake2b512.to_bytes())
        }
    }
}

#[derive(Clone)]
pub struct DigestAlgorithm<MD: MessageDigestTrait> {
    md: PhantomData<MD>,
    ctx: EvpMdCtx,
}

impl<MD: MessageDigestTrait> OutputSizeUser for DigestAlgorithm<MD> {
    type OutputSize = MD::OutputSize;
}

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

    #[test]
    fn test_ripemd160_hash() {
        let message = b"hello world";
        let expected_hash = hex!("98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f");
        let result = DigestAlgorithm::<RIPEMD160>::digest(message);

        assert_eq!(
            result.as_slice(),
            &expected_hash[..],
            "The RIPEMD160 hash does not match the expected value"
        );
    }

    #[test]
    fn test_whirlpool_hash() { // TODO: CRASH
        let message = b"hello world";
        let expected_hash = hex!(
            "e45c86e04a1bcfa3a625b48ebcb1c3e5e7f7a25b2da41d97f0fb5f7b98778c5db1e2e282cae6a1a8e71b464c5f4749a0d037d86dfe3d2c36721e35315be8b8f1"
        );
        let result = DigestAlgorithm::<Whirlpool>::digest(message);

        assert_eq!(
            result.as_slice(),
            &expected_hash[..],
            "The Whirlpool hash does not match the expected value"
        );
    }

    #[test]
    fn test_sha3_256_hash() { // TODO: NO MATCH
        let message = b"hello world";
        let expected_hash =
            hex!("644bcc7e56437304038e0d55a8dbd0b9ba61a659bbf2f21c3f9dbaf0c5af8e07");
        let result = DigestAlgorithm::<SHA3_256>::digest(message);

        assert_eq!(
            result.as_slice(),
            &expected_hash[..],
            "The SHA3-256 hash does not match the expected value"
        );
    }

    #[test]
    fn test_blake2b512_hash() { // TODO: NO MATCH
        let message = b"hello world";
        let expected_hash = hex!(
            "6f56a1f7a0a306a8531ffb39a7c193bbbc8e3d81f262f947e47e56e62e37e6cb232d212e666ee74c6c88c765f3fd472f2c1396e6173346e7fb47b37a36f5e0b3"
        );
        let result = DigestAlgorithm::<BLAKE2b512>::digest(message);

        assert_eq!(
            result.as_slice(),
            &expected_hash[..],
            "The BLAKE2b-512 hash does not match the expected value"
        );
    }
}
