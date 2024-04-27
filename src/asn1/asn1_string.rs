use foreign_types::{foreign_type, ForeignType};

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
            let s = Self::from_ptr(ASN1_STRING_type_new(asn1_type as i32));
            ASN1_STRING_set0(s.as_ptr(), data.as_ptr() as *mut _, data.len() as i32);
            s
        }
    }

    pub fn get_type(&self) -> Asn1Type {
        todo!()
    }
}
