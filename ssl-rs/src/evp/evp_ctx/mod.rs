mod ec;
mod rsa;

use foreign_types::{foreign_type, ForeignType};
use std::ffi::c_char;

use crate::{error::ErrorStack, ossl_param::OsslParamRef, ssl::*};

use super::{EvpId, EvpPkey, KeyAlgorithm, KeyType, Private};

foreign_type! {
    pub unsafe type EvpCtx<KT: KeyType> {
        type CType = EVP_PKEY_CTX;
        type PhantomData = KT;
        fn drop = EVP_PKEY_CTX_free;
        fn clone = EVP_PKEY_CTX_dup;
    }
}

impl<KT: KeyType> EvpCtx<KT> {}

impl<KT: KeyType> TryFrom<EvpId> for EvpCtx<KT> {
    type Error = ErrorStack;

    fn try_from(value: EvpId) -> Result<Self, Self::Error> {
        unsafe {
            crate::check_ptr(EVP_PKEY_CTX_new_id(
                value.get_raw() as i32,
                std::ptr::null_mut(),
            ))
            .map(|v| Self::from_ptr(v))
        }
    }
}

impl<KT: KeyType> TryFrom<&str> for EvpCtx<KT> {
    type Error = ErrorStack;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        unsafe {
            crate::check_ptr(EVP_PKEY_CTX_new_from_name(
                std::ptr::null_mut(),
                value.as_ptr() as *const c_char,
                std::ptr::null_mut(),
            ))
            .map(|v| Self::from_ptr(v))
        }
    }
}

impl<KT: KeyType> TryFrom<&EvpPkey<Private>> for EvpCtx<KT> {
    type Error = ErrorStack;

    fn try_from(value: &EvpPkey<Private>) -> Result<Self, Self::Error> {
        unsafe {
            crate::check_ptr(EVP_PKEY_CTX_new_from_pkey(
                std::ptr::null_mut(),
                value.as_ptr(),
                std::ptr::null_mut(),
            ))
            .map(|v| Self::from_ptr(v))
        }
    }
}

pub trait KeyGen<KA: KeyAlgorithm> {
    fn generate(self, alg: KA) -> Result<EvpPkey<Private>, ErrorStack>;
}

pub trait ParamsKeyGen<KA: KeyAlgorithm> {
    fn generate_with_params(self, params: &OsslParamRef) -> Result<EvpPkey<Private>, ErrorStack>;
}
