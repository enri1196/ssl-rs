use std::ffi::c_void;

use foreign_types::{foreign_type, ForeignType};
use num::FromPrimitive;

use crate::ssl::*;

use super::Asn1Type;

foreign_type! {
    pub unsafe type Asn1String: Sync + Send {
        type CType = ASN1_STRING;
        fn drop = ASN1_STRING_free;
        fn clone = ASN1_STRING_dup;
    }
}

impl Asn1String {
    pub fn new(asn1_type: Asn1Type, data: &[u8]) -> Self {
        unsafe {
            let asn1_str = Self::from_ptr(ASN1_STRING_type_new(asn1_type as i32));
            ASN1_STRING_set(
                asn1_str.as_ptr(),
                data.as_ptr() as *mut c_void,
                data.len() as i32,
            );
            asn1_str
        }
    }

    pub fn get_type(&self) -> Asn1Type {
        unsafe {
            // SAFETY: this should not panic since the contained type should
            // always be a valid asn1 type
            Asn1Type::from_i32(ASN1_STRING_type(self.as_ptr())).unwrap_unchecked()
        }
    }
}
