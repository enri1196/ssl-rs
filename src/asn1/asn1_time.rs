use std::fmt::Display;

use foreign_types::{foreign_type, ForeignTypeRef};

use crate::{bio::SslBio, ssl::*};

foreign_type! {
    pub unsafe type Asn1Time: Sync + Send {
        type CType = ASN1_TIME;
        fn drop = ASN1_TIME_free;
        fn clone = ASN1_TIME_dup;
    }
}

impl PartialEq for Asn1TimeRef {
    fn eq(&self, other: &Self) -> bool {
        unsafe { ASN1_TIME_compare(self.as_ptr(), other.as_ptr()) == 0 }
    }
}

impl PartialOrd for Asn1TimeRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        unsafe {
            match ASN1_TIME_compare(self.as_ptr(), other.as_ptr()) {
                -1 => Some(std::cmp::Ordering::Less),
                0 => Some(std::cmp::Ordering::Equal),
                1 => Some(std::cmp::Ordering::Greater),
                _ => None,
            }
        }
    }
}

impl Asn1Time {}

impl Display for Asn1TimeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bio = SslBio::memory();
            ASN1_TIME_print_ex(bio.as_ptr(), self.as_ptr() as *const _, 0);
            write!(f, "{}", std::str::from_utf8(bio.get_data()).unwrap())
        }
    }
}
