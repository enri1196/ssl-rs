use foreign_types::{foreign_type, ForeignType};

use crate::{error::ErrorStack, ssl::*};

foreign_type! {
    pub unsafe type OcspResp: Sync + Send {
        type CType = OCSP_RESPONSE;
        fn drop = OCSP_RESPONSE_free;
    }
}

impl TryFrom<&[u8]> for OcspResp {
    type Error = ErrorStack;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        unsafe {
            let ptr = crate::check_ptr(d2i_OCSP_RESPONSE(
                std::ptr::null_mut(),
                value.as_ptr() as *mut *const _,
                value.len() as i64,
            ))?;
            Ok(Self::from_ptr(ptr))
        }
    }
}
