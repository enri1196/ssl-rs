use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::ssl::*;

foreign_type! {
    pub unsafe type Asn1OctetString: Sync + Send {
        type CType = ASN1_OCTET_STRING;
        fn drop = ASN1_OCTET_STRING_free;
        fn clone = ASN1_OCTET_STRING_dup;
    }
}

impl Asn1OctetString {
    pub fn new() -> Asn1OctetString {
        unsafe { Asn1OctetString::from_ptr(ASN1_OCTET_STRING_new()) }
    }
}

impl Asn1OctetStringRef {
    pub fn len(&self) -> usize {
        unsafe { ASN1_STRING_length(self.as_ptr() as *const _) as usize }
    }
}

impl Default for Asn1OctetString {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&str> for Asn1OctetString {
    fn from(value: &str) -> Self {
        unsafe {
            let ptr = Asn1OctetString::new();
            ASN1_OCTET_STRING_set(ptr.as_ptr(), value.as_ptr(), value.len() as i32);
            ptr
        }
    }
}

#[cfg(test)]
mod test {
    use crate::asn1::Asn1OctetString;

    #[test]
    fn str_len() {
        let aos = Asn1OctetString::from("Hello, World!");
        assert_eq!(aos.len(), 13)
    }
}
