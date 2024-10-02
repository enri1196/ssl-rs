use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::{
    asn1::{Asn1IntegerRef, Asn1ObjectRef, Asn1OctetStringRef},
    error::ErrorStack,
    ssl::*,
    x509::{X509AlgRef, X509ExtRef},
};

foreign_type! {
    pub unsafe type TsReq: Sync + Send {
        type CType = TS_REQ;
        fn drop = TS_REQ_free;
        fn clone = TS_REQ_dup;
    }
}

impl TsReqRef {
    pub fn get_version(&self) -> i64 {
        unsafe { TS_REQ_get_version(self.as_ptr()) }
    }

    pub fn get_msg_imprint(&self) -> &TsMsgImprintRef {
        unsafe { TsMsgImprintRef::from_ptr(TS_REQ_get_msg_imprint(self.as_ptr())) }
    }

    pub fn get_req_policy(&self) -> Option<&TsaPolicyId> {
        unsafe {
            let ptr = TS_REQ_get_policy_id(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(TsaPolicyId::from_ptr(ptr))
            }
        }
    }

    pub fn get_nonce(&self) -> Option<&Asn1IntegerRef> {
        unsafe {
            let ptr = TS_REQ_get_nonce(self.as_ptr()) as *mut ASN1_INTEGER;
            if ptr.is_null() {
                None
            } else {
                Some(Asn1IntegerRef::from_ptr(ptr))
            }
        }
    }

    pub fn get_cert_req(&self) -> bool {
        unsafe { TS_REQ_get_cert_req(self.as_ptr()) == 1 }
    }

    pub fn get_ext(&self, idx: i32) -> Option<&X509ExtRef> {
        unsafe {
            let ptr = TS_REQ_get_ext(self.as_ptr(), idx);
            if ptr.is_null() {
                None
            } else {
                Some(X509ExtRef::from_ptr(ptr))
            }
        }
    }

    pub fn get_ext_len(&self) -> usize {
        unsafe { TS_REQ_get_ext_count(self.as_ptr()) as usize }
    }
}

impl TryFrom<&[u8]> for TsReq {
    type Error = ErrorStack;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        unsafe {
            let ptr = crate::check_ptr(d2i_TS_REQ(
                std::ptr::null_mut(),
                value.as_ptr() as *mut *const _,
                value.len() as i64,
            ))?;
            Ok(Self::from_ptr(ptr))
        }
    }
}

foreign_type! {
    pub unsafe type TsMsgImprint: Sync + Send {
        type CType = TS_MSG_IMPRINT;
        fn drop = TS_MSG_IMPRINT_free;
        fn clone = TS_MSG_IMPRINT_dup;
    }
}

impl TsMsgImprintRef {
    pub fn get_hash_algorithm(&self) -> &X509AlgRef {
        unsafe { X509AlgRef::from_ptr(TS_MSG_IMPRINT_get_algo(self.as_ptr())) }
    }

    pub fn get_hashed_msg(&self) -> &Asn1OctetStringRef {
        unsafe { Asn1OctetStringRef::from_ptr(TS_MSG_IMPRINT_get_msg(self.as_ptr())) }
    }
}

type TsaPolicyId = Asn1ObjectRef;
