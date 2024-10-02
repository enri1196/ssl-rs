use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use num::FromPrimitive;
use num_derive::FromPrimitive;

use crate::{asn1::Asn1IntegerRef, error::ErrorStack, ssl::*};

foreign_type! {
    pub unsafe type TsResp: Sync + Send {
        type CType = TS_RESP;
        fn drop = TS_RESP_free;
        fn clone = TS_RESP_dup;
    }
}

impl TsRespRef {
    pub fn get_status_info(&self) -> &TsStatusInfoRef {
        unsafe { TsStatusInfoRef::from_ptr(TS_RESP_get_status_info(self.as_ptr())) }
    }

    pub fn get_token(&self) -> Option<()> {
        unsafe {
            TS_RESP_get_token(self.as_ptr());
            None
        }
    }

    pub fn get_status(&self) -> Result<PkiStatus, PkiFailureInfo> {
        unsafe {
            let ptr = TS_STATUS_INFO_get0_status(self.as_ptr() as *const _);
            let asn1_int = Asn1IntegerRef::from_ptr(ptr as *mut _);
            match self.get_token() {
                Some(_) => Ok(PkiStatus::from_u64(asn1_int.into()).unwrap()),
                None => Err(PkiFailureInfo::from_u64(asn1_int.into()).unwrap()),
            }
        }
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

foreign_type! {
    pub unsafe type TsTstInfo: Sync + Send {
        type CType = TS_TST_INFO;
        fn drop = TS_TST_INFO_free;
        fn clone = TS_TST_INFO_dup;
    }
}

foreign_type! {
    pub unsafe type TsStatusInfo: Sync + Send {
        type CType = TS_STATUS_INFO;
        fn drop = TS_STATUS_INFO_free;
        fn clone = TS_STATUS_INFO_dup;
    }
}

impl TsStatusInfoRef {
    pub fn get_status_raw(&self) -> u64 {
        unsafe {
            let ptr = TS_STATUS_INFO_get0_status(self.as_ptr() as *const _);
            let asn1_int = Asn1IntegerRef::from_ptr(ptr as *mut _);
            asn1_int.into()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, FromPrimitive)]
#[repr(u64)]
pub enum PkiStatus {
    /// when the PKIStatus contains the value zero a TimeStampToken, as
    /// requested, is present.
    Granted,
    /// when the PKIStatus contains the value one a TimeStampToken,
    /// with modifications, is present.
    GrantedWithMods,
    Rejection,
    Waiting,
    /// this message contains a warning that a revocation is
    /// imminent
    RevocationWarning,
    /// notification that a revocation has occurred
    RevocationNotification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, FromPrimitive)]
#[repr(u64)]
pub enum PkiFailureInfo {
    /// unrecognized or unsupported Algorithm Identifier
    BadAlg,
    /// transaction not permitted or supported
    BadRequest,
    /// the data submitted has the wrong format
    BadDataFormat,
    /// the TSA's time source is not available
    TimeNotAvailable,
    /// the requested TSA policy is not supported by the TSA
    UnacceptedPolicy,
    /// the requested extension is not supported by the TSA
    UnacceptedExtension,
    /// the additional information requested could not be understood
    /// or is not avai,
    AddInfoNotAvailable,
    /// the request cannot be handled due to system failure
    SystemFailure,
}
