use std::fmt::Display;

use chrono::{DateTime, Utc};
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

impl Asn1TimeRef {
    pub fn to_date_time(&self) -> Option<DateTime<Utc>> {
        unsafe {
            let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
            ASN1_TIME_to_tm(self.as_ptr(), tm.as_mut_ptr() as *mut _);
            let secs = libc::mktime(tm.as_mut_ptr());
            DateTime::from_timestamp(secs, 0)
        }
    }
}

impl Display for Asn1TimeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bio = SslBio::memory();
            ASN1_TIME_print_ex(bio.as_ptr(), self.as_ptr() as *const _, 0);
            write!(f, "{}", std::str::from_utf8_unchecked(bio.get_data()))
        }
    }
}
