use foreign_types::{foreign_type, ForeignType};

use crate::{error::ErrorStack, ssl::*};

foreign_type! {
    pub unsafe type TsResp: Sync + Send {
        type CType = TS_RESP;
        fn drop = TS_RESP_free;
        fn clone = TS_RESP_dup;
    }
}

impl TryFrom<&[u8]> for TsResp {
    type Error = ErrorStack;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        unsafe {
            let ptr = crate::check_ptr(d2i_TS_RESP(
                std::ptr::null_mut(),
                value.as_ptr() as *mut *const _,
                value.len() as i64,
            ))?;
            Ok(Self::from_ptr(ptr))
        }
    }
}
