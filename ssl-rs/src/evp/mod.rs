pub mod digest;
pub mod ec;
pub mod ecdh;
mod evp_ctx;
pub mod rsa;

use num_derive::FromPrimitive;
use std::fmt::Display;

use crate::{bio::SslBio, error::ErrorStack, ossl_param::OsslParamRef, ssl::*};

use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use self::evp_ctx::EvpCtx;

pub struct Private;
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
            let ctx = EvpCtx::try_from(self)?;
            crate::check_code(EVP_PKEY_sign_init(ctx.as_ptr()))?;
            let mut siglen = 0;
            crate::check_code(EVP_PKEY_sign(
                ctx.as_ptr(),
                std::ptr::null_mut(),
                &mut siglen,
                tbs.as_ptr(),
                tbs.len(),
            ))?;
            let mut sig = Vec::with_capacity(siglen);
            crate::check_code(EVP_PKEY_sign(
                ctx.as_ptr(),
                sig.as_mut_ptr(),
                &mut siglen,
                tbs.as_ptr(),
                tbs.len(),
            ))?;
            Ok(sig)
        }
    }
}

impl<KT: KeyType> Default for EvpPkey<KT> {
    fn default() -> Self {
        unsafe { Self::from_ptr(EVP_PKEY_new()) }
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

impl TryFrom<EvpPkey<Private>> for EvpPkey<Public> {
    type Error = ErrorStack;
    fn try_from(value: EvpPkey<Private>) -> Result<Self, Self::Error> {
        value.get_public()
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

#[cfg(test)]
mod test {
    use crate::evp::{
        ec::{CurveNid, CurveRawNid, EcKey},
        rsa::{RsaKey, RsaSize},
        Private,
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
    pub fn test_raw_ec() {
        let key = EcKey::<Private>::new_raw_ec(CurveRawNid::X25519).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        // assert_eq!(408, key.id().get_raw());
        // assert_eq!(72, key.size());
    }
}
