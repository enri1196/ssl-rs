use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use std::ffi::c_char;

use crate::{error::ErrorStack, ssl::*};

use super::{EvpId, EvpPkeyRef, Private, Public};

foreign_type! {
    pub unsafe type EvpCtx {
        type CType = EVP_PKEY_CTX;
        fn drop = EVP_PKEY_CTX_free;
        fn clone = EVP_PKEY_CTX_dup;
    }
}

impl From<EvpId> for EvpCtx {
    fn from(value: EvpId) -> Self {
        unsafe {
            Self::from_ptr(EVP_PKEY_CTX_new_id(
                value.get_raw() as i32,
                std::ptr::null_mut(),
            ))
        }
    }
}

impl TryFrom<&str> for EvpCtx {
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

impl TryFrom<&EvpPkeyRef<Private>> for EvpCtx {
    type Error = ErrorStack;

    fn try_from(value: &EvpPkeyRef<Private>) -> Result<Self, Self::Error> {
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

impl TryFrom<&EvpPkeyRef<Public>> for EvpCtx {
    type Error = ErrorStack;

    fn try_from(value: &EvpPkeyRef<Public>) -> Result<Self, Self::Error> {
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
