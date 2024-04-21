use std::os::raw::c_char;

use foreign_types::{foreign_type, ForeignType};

use crate::{bn::BigNum, ssl::*};

foreign_type! {
    pub unsafe type OsslParam: Sync + Send {
        type CType = OSSL_PARAM;
        fn drop = OSSL_PARAM_free;
    }
}

foreign_type! {
    pub unsafe type OsslParamBld: Sync + Send {
        type CType = OSSL_PARAM_BLD;
        fn drop = OSSL_PARAM_BLD_free;
    }
}

impl OsslParamBld {
    pub fn new() -> OsslParamBld {
        unsafe { OsslParamBld::from_ptr(OSSL_PARAM_BLD_new()) }
    }

    pub fn push_bn(self, key: &str, bn: BigNum) -> Self {
        unsafe {
            let key = key.as_ptr() as *mut c_char;
            OSSL_PARAM_BLD_push_BN(self.as_ptr(), key, bn.as_ptr());
            self
        }
    }

    pub fn push_u32(self, key: &str, value: u32) -> Self {
        unsafe {
            let key = key.as_ptr() as *const c_char;
            OSSL_PARAM_BLD_push_uint32(self.as_ptr(), key, value);
            self
        }
    }

    pub fn to_ossl_param(self) -> OsslParam {
        unsafe { OsslParam::from_ptr(OSSL_PARAM_BLD_to_param(self.as_ptr())) }
    }
}
