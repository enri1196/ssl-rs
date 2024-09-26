pub mod cipher;
pub mod digest;
pub mod ec;
pub mod ecdh;
mod evp_ctx;
pub mod hkdf;
pub mod mac_alg;
pub mod rsa;

use num_derive::FromPrimitive;
use std::fmt::Display;

use crate::{bio::SslBio, error::ErrorStack, ossl_param::OsslParamRef, ssl::*};

use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use self::evp_ctx::EvpCtx;

#[derive(Clone, Copy)]
pub struct Private;

#[derive(Clone, Copy)]
pub struct Public;

pub trait KeyType {}
impl KeyType for Private {}
impl KeyType for Public {}

#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
#[repr(u32)]
pub enum EvpId {
    RsaId = EVP_PKEY_RSA,
    RsaPssId = EVP_PKEY_RSA_PSS,
    EcId = EVP_PKEY_EC,
    X25519Id = EVP_PKEY_X25519,
    X448Id = EVP_PKEY_X448,
    Ed25519Id = EVP_PKEY_ED25519,
    Ed448Id = EVP_PKEY_ED448,
    Hkdf = EVP_PKEY_HKDF,
}

impl EvpId {
    pub fn get_raw(&self) -> u32 {
        *self as u32
    }
}

foreign_type! {
    pub unsafe type EvpPkey<KT: KeyType> : Send + Sync {
        type CType = EVP_PKEY;
        type PhantomData = KT;
        fn drop = EVP_PKEY_free;
        fn clone = EVP_PKEY_dup;
    }
}

impl EvpPkey<Private> {
    pub fn get_public(&self) -> Result<EvpPkey<Public>, ErrorStack> {
        self.as_ref().get_public()
    }

    pub fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        self.as_ref().sign(tbs)
    }
}

impl EvpPkeyRef<Private> {
    pub fn get_public(&self) -> Result<EvpPkey<Public>, ErrorStack> {
        unsafe {
            let bio = SslBio::memory();
            crate::check_code(PEM_write_bio_PUBKEY(bio.as_ptr(), self.as_ptr()))?;
            crate::check_ptr(PEM_read_bio_PUBKEY(
                bio.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            ))
            .map(|ptr| EvpPkey::<Public>::from_ptr(ptr))
        }
    }

    pub fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let mdctx = EvpMdCtx::default();
            crate::check_code(EVP_DigestSignInit(
                mdctx.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                self.as_ptr(),
            ))?;
            let mut siglen = 0;
            crate::check_code(EVP_DigestSign(
                mdctx.as_ptr(),
                std::ptr::null_mut(),
                &mut siglen,
                tbs.as_ptr(),
                tbs.len(),
            ))?;
            let mut sig = Vec::with_capacity(siglen as usize);
            crate::check_code(EVP_DigestSign(
                mdctx.as_ptr(),
                sig.as_mut_ptr(),
                &mut siglen,
                tbs.as_ptr(),
                tbs.len(),
            ))?;
            sig.set_len(siglen);
            Ok(sig)
        }
    }
}

impl EvpPkey<Public> {
    pub fn verify_sign(&self, tbs: &[u8], signature: &[u8]) -> Result<bool, ErrorStack> {
        self.as_ref().verify_sign(tbs, signature)
    }
}

impl EvpPkeyRef<Public> {
    pub fn verify_sign(&self, tbs: &[u8], signature: &[u8]) -> Result<bool, ErrorStack> {
        unsafe {
            let vctx = EvpMdCtx::default();
            crate::check_code(EVP_DigestVerifyInit(
                vctx.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                self.as_ptr(),
            ))?;
            let verify = crate::check_code(EVP_DigestVerify(
                vctx.as_ptr(),
                signature.as_ptr(),
                signature.len(),
                tbs.as_ptr(),
                tbs.len(),
            ))?;
            Ok(verify == 1)
        }
    }
}

impl<KT: KeyType> Default for EvpPkey<KT> {
    fn default() -> Self {
        unsafe { Self::from_ptr(EVP_PKEY_new()) }
    }
}

impl TryFrom<EvpCtx> for EvpPkey<Private> {
    type Error = ErrorStack;

    fn try_from(ctx: EvpCtx) -> Result<Self, Self::Error> {
        unsafe {
            let m_key = EvpPkey::<Private>::default();
            crate::check_code(EVP_PKEY_keygen_init(ctx.as_ptr()))?;
            crate::check_code(EVP_PKEY_generate(
                ctx.as_ptr(),
                &mut m_key.as_ptr() as *mut *mut _,
            ))?;
            Ok(m_key)
        }
    }
}

impl TryFrom<(EvpCtx, &OsslParamRef)> for EvpPkey<Private> {
    type Error = ErrorStack;

    fn try_from((ctx, params): (EvpCtx, &OsslParamRef)) -> Result<Self, Self::Error> {
        unsafe {
            let m_key = EvpPkey::<Private>::default();
            crate::check_code(EVP_PKEY_keygen_init(ctx.as_ptr()))?;
            crate::check_code(EVP_PKEY_CTX_set_params(
                ctx.as_ptr(),
                params.as_ptr() as *const _,
            ))?;
            crate::check_code(EVP_PKEY_generate(
                ctx.as_ptr(),
                &mut m_key.as_ptr() as *mut *mut _,
            ))?;
            Ok(m_key)
        }
    }
}

impl Display for EvpPkeyRef<Private> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bio = SslBio::memory();
            crate::check_code(PEM_write_bio_PrivateKey_ex(
                bio.as_ptr(),
                self.as_ptr() as *const _,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                None,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ))
            .unwrap();
            match bio.get_data() {
                Some(data) => write!(f, "{}", std::str::from_utf8_unchecked(data)),
                None => Err(std::fmt::Error),
            }
        }
    }
}

impl Display for EvpPkeyRef<Public> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bio = SslBio::memory();
            crate::check_code(PEM_write_bio_PUBKEY_ex(
                bio.as_ptr(),
                self.as_ptr() as *const _,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ))
            .unwrap();
            match bio.get_data() {
                Some(data) => write!(f, "{}", std::str::from_utf8_unchecked(data)),
                None => Err(std::fmt::Error),
            }
        }
    }
}

foreign_type! {
    pub unsafe type EvpMdCtx : Send + Sync {
        type CType = EVP_MD_CTX;
        fn drop = EVP_MD_CTX_free;
    }
}

impl Default for EvpMdCtx {
    fn default() -> Self {
        unsafe { Self::from_ptr(EVP_MD_CTX_new()) }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        error::ErrorStack,
        evp::{
            ec::{CurveNid, CurveRawNid, EcKey},
            rsa::{RsaKey, RsaSize},
            Private,
        },
    };

    #[test]
    pub fn test_rsa() {
        let key = RsaKey::new_rsa(RsaSize::Rs2048).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        // assert_eq!(6, key.id().get_raw());
        // assert_eq!(256, key.size());
    }

    #[test]
    pub fn test_ec() {
        let key = EcKey::<Private>::new_ec(CurveNid::Prime256v1).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        // assert_eq!(408, key.id().get_raw());
        // assert_eq!(72, key.size());
    }

    #[test]
    pub fn test_raw_ec1() {
        let key = EcKey::<Private>::new_raw_ec(CurveRawNid::X25519).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        // assert_eq!(408, key.id().get_raw());
        // assert_eq!(72, key.size());
    }

    #[test]
    pub fn test_raw_ec2() {
        let key = EcKey::<Private>::new_raw_ec(CurveRawNid::ED25519).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        // assert_eq!(408, key.id().get_raw());
        // assert_eq!(72, key.size());
    }

    #[test]
    fn test_sign_and_verify_ed25519() -> Result<(), ErrorStack> {
        let ec_key = EcKey::<Private>::new_raw_ec(CurveRawNid::ED25519)
            .expect("Failed to create EC Private Key");

        let message = b"The quick brown fox jumps over the lazy dog";

        let signature = ec_key.sign(message).expect("Failed to sign the message");

        let evp_pkey_public = ec_key.get_public().expect("Failed to extract public key");

        evp_pkey_public
            .verify_sign(message, &signature)
            .expect("Failed to verify the signature");

        Ok(())
    }
}
