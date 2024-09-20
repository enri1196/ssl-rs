use std::os::raw::c_char;

use foreign_types::{foreign_type, ForeignType};

use crate::{bn::BigNum, ssl::*};

foreign_type! {
    pub unsafe type OsslParam: Sync + Send {
        type CType = OSSL_PARAM;
        fn drop = OSSL_PARAM_free;
        fn clone = OSSL_PARAM_dup;
    }
}

foreign_type! {
    pub unsafe type OsslParamBld: Sync + Send {
        type CType = OSSL_PARAM_BLD;
        fn drop = OSSL_PARAM_BLD_free;
    }
}

impl Default for OsslParamBld {
    fn default() -> Self {
        Self::new()
    }
}

impl OsslParamBld {
    pub fn new() -> OsslParamBld {
        unsafe { OsslParamBld::from_ptr(OSSL_PARAM_BLD_new()) }
    }

    pub fn push_bn(self, key: &str, bn: BigNum) -> Self {
        unsafe {
            OSSL_PARAM_BLD_push_BN(self.as_ptr(), key.as_ptr() as *const c_char, bn.as_ptr());
            self
        }
    }

    pub fn push_u32(self, key: &str, value: u32) -> Self {
        unsafe {
            OSSL_PARAM_BLD_push_uint32(self.as_ptr(), key.as_ptr() as *const c_char, value);
            self
        }
    }

    pub fn push_str(self, key: &str, value: &str) -> Self {
        unsafe {
            crate::check_code(OSSL_PARAM_BLD_push_utf8_string(
                self.as_ptr(),
                key.as_ptr() as *const c_char,
                value.as_ptr() as *const c_char,
                value.len(),
            ))
            .expect("OSSL_PARAM_BLD_push_utf8_string failed");
            self
        }
    }

    pub fn build(self) -> OsslParam {
        unsafe { OsslParam::from_ptr(OSSL_PARAM_BLD_to_param(self.as_ptr())) }
    }
}
