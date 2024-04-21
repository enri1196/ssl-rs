mod evp_ctx;
mod evp_props;

use std::fmt::Display;

use crate::{bio::SslBio, error::ErrorStack, ssl::*};

pub use evp_props::*;
use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use self::evp_ctx::EvpCtx;

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
        unsafe { EvpId::from(EVP_PKEY_get_id(self.as_ptr()) as u32) }
    }

    pub fn size(&self) -> i32 {
        unsafe { EVP_PKEY_get_size(self.as_ptr()) }
    }
}

impl EvpPkey<Private> {
    pub fn get_public(&self) -> Result<EvpPkey<Public>, ErrorStack> {
        match self.id() {
            _ => todo!(),
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
        EvpCtx::<Private, RsaKey>::generate(value)
    }
}

impl TryFrom<EcKey> for EvpPkey<Private> {
    type Error = ErrorStack;
    fn try_from(value: EcKey) -> Result<Self, Self::Error> {
        EvpCtx::<Private, EcKey>::generate(value)
    }
}

impl TryFrom<DsaKey> for EvpPkey<Private> {
    type Error = ErrorStack;
    fn try_from(value: DsaKey) -> Result<Self, Self::Error> {
        EvpCtx::<Private, DsaKey>::generate(value)
    }
}

impl TryFrom<EvpPkey<Private>> for EvpPkey<Public> {
    type Error = ErrorStack;
    fn try_from(value: EvpPkey<Private>) -> Result<Self, Self::Error> {
        value.get_public()
    }
}

impl Display for EvpPkey<Private> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let mem = SslBio::memory();
            crate::check_code(PEM_write_bio_PrivateKey_ex(
                mem.as_ptr(),
                self.as_ptr() as *const _,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                None,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ))
            .unwrap();
            write!(f, "")
        }
    }
}
