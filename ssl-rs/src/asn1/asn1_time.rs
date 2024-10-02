use std::{fmt::Display, time::Duration};

use chrono::{DateTime, Utc};
use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::{bio::SslBio, error::ErrorStack, ssl::*};

foreign_type! {
    pub unsafe type Asn1Time: Sync + Send {
        type CType = ASN1_TIME;
        fn drop = ASN1_TIME_free;
        fn clone = ASN1_TIME_dup;
    }
}

impl Asn1Time {
    pub fn now() -> Result<Self, ErrorStack> {
        unsafe {
            let now = libc::time(std::ptr::null_mut());
            let ptr = ASN1_TIME_set(std::ptr::null_mut(), now);
            if ptr.is_null() {
                Err(ErrorStack::get())
            } else {
                Ok(Asn1Time::from_ptr(ptr))
            }
        }
    }

    pub fn add_duration(&self, duration: Duration) -> Asn1Time {
        unsafe {
            let new_time = self.clone();
            let secs = duration.as_secs();
            ASN1_TIME_set(new_time.as_ptr(), secs as i64);
            new_time
        }
    }

    pub fn to_date_time(&self) -> Option<DateTime<Utc>> {
        self.as_ref().to_date_time()
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

impl TryFrom<&DateTime<Utc>> for Asn1Time {
    type Error = ErrorStack;

    fn try_from(value: &DateTime<Utc>) -> Result<Self, Self::Error> {
        unsafe {
            let time = value.timestamp() as time_t;
            let ptr = ASN1_TIME_set(std::ptr::null_mut(), time);
            if ptr.is_null() {
                Err(ErrorStack::get())
            } else {
                Ok(Asn1Time::from_ptr(ptr))
            }
        }
    }
}

impl PartialEq for Asn1Time {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().eq(&other.as_ref())
    }
}

impl PartialEq for &Asn1TimeRef {
    fn eq(&self, other: &Self) -> bool {
        unsafe { ASN1_TIME_compare(self.as_ptr(), other.as_ptr()) == 0 }
    }
}

impl PartialOrd for Asn1Time {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(&other.as_ref())
    }
}

impl PartialOrd for &Asn1TimeRef {
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

impl Display for Asn1Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl Display for &Asn1TimeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bio = SslBio::memory();
            ASN1_TIME_print_ex(bio.as_ptr(), self.as_ptr() as *const _, 0);
            write!(
                f,
                "{}",
                std::str::from_utf8_unchecked(bio.get_data().unwrap())
            )
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use crate::asn1::Asn1Time;

    #[test]
    fn time_display() {
        let aos = Asn1Time::now().unwrap();
        let aos = aos.add_duration(Duration::from_days(10));
        assert_eq!(aos.to_string(), "Jan 11 00:00:00 1970 GMT")
    }
}
