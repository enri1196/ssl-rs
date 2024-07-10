mod evp_ctx;
mod evp_props;

use std::fmt::Display;

use crate::{bio::SslBio, error::ErrorStack, ssl::*};

pub use evp_props::*;
use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use num::FromPrimitive;

use self::evp_ctx::{EvpCtx, KeyGen};

foreign_type! {
    pub unsafe type EvpPkey<KT: KeyType> : Send + Sync {
        type CType = EVP_PKEY;
        type PhantomData = KT;
        fn drop = EVP_PKEY_free;
        fn clone = EVP_PKEY_dup;
    }
}

impl<KT: KeyType> EvpPkeyRef<KT> {
    pub fn id(&self) -> EvpId {
        unsafe { EvpId::from_u32(EVP_PKEY_get_id(self.as_ptr()) as u32).unwrap_unchecked() }
    }

    pub fn size(&self) -> i32 {
        unsafe { EVP_PKEY_get_size(self.as_ptr()) }
    }
}

impl EvpPkey<Private> {
    pub fn get_public(&self) -> Result<EvpPkey<Public>, ErrorStack> {
        unsafe {
            let bio = SslBio::memory();
            crate::check_code(PEM_write_bio_PUBKEY(bio.as_ptr(), self.as_ptr()))?;
            let pub_key = crate::check_ptr(PEM_read_bio_PUBKEY(
                bio.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            ))?;

            Ok(EvpPkey::<Public>::from_ptr(pub_key))
        }
    }

    pub fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let ctx = EVP_PKEY_CTX_new_from_pkey(std::ptr::null_mut(), self.as_ptr(), std::ptr::null_mut());
            crate::check_code(EVP_PKEY_sign_init(ctx))?;
            let mut siglen = 0;
            crate::check_code(EVP_PKEY_sign(ctx, std::ptr::null_mut(), &mut siglen, tbs.as_ptr(), tbs.len()))?;
            let mut sig = Vec::with_capacity(siglen);
            crate::check_code(EVP_PKEY_sign(ctx, sig.as_mut_ptr(), &mut siglen, tbs.as_ptr(), tbs.len()))?;
            Ok(sig)
        }
    }
}

impl<KT: KeyType> Default for EvpPkey<KT> {
    fn default() -> Self {
        unsafe { Self::from_ptr(EVP_PKEY_new()) }
    }
}

impl TryFrom<RsaKey> for EvpPkey<Private> {
    type Error = ErrorStack;
    fn try_from(value: RsaKey) -> Result<Self, Self::Error> {
        let RsaKey(evp_id, _) = value;
        EvpCtx::from(evp_id)
            .generate(value)
    }
}

impl TryFrom<EcKey> for EvpPkey<Private> {
    type Error = ErrorStack;
    fn try_from(value: EcKey) -> Result<Self, Self::Error> {
        let EcKey(evp_id, _) = value;
        EvpCtx::from(evp_id)
            .generate(value)
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
            write!(f, "{}", std::str::from_utf8_unchecked(bio.get_data()))
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
            write!(f, "{}", std::str::from_utf8_unchecked(bio.get_data()))
        }
    }
}
