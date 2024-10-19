use std::{ffi::CString, fmt::Display};

use foreign_types::ForeignType;

use crate::{error::ErrorStack, ssl::*, x509::X509Ext};

use super::{ToExt, X509ExtNid};

#[derive(Default)]
pub struct BasicConstraints {
    critical: bool,
    ca: bool,
    pathlen: Option<u32>,
}

impl BasicConstraints {
    pub fn new(critical: bool, ca: bool, pathlen: Option<u32>) -> Self {
        Self {
            critical,
            ca,
            pathlen,
        }
    }
}

impl Display for BasicConstraints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut value = String::with_capacity(30);
        if self.critical {
            value.push_str("critical,");
        }
        if self.ca {
            value.push_str("CA:TRUE");
        } else {
            value.push_str("CA:FALSE");
        }
        if let Some(pathlen) = self.pathlen {
            value.push_str(&format!(",pathlen:{pathlen}"))
        }
        write!(f, "{value}")
    }
}

impl ToExt for BasicConstraints {
    fn to_ext(&self) -> Result<X509Ext, ErrorStack> {
        unsafe {
            let mut ctx = std::mem::zeroed::<v3_ext_ctx>();
            X509V3_set_ctx(
                &mut ctx,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            );

            let value = CString::new(self.to_string()).expect("Cstring Nul error");
            let ptr = crate::check_ptr(X509V3_EXT_conf_nid(
                std::ptr::null_mut(),
                &mut ctx,
                X509ExtNid::BASIC_CONSTRAINTS.nid(),
                value.as_ptr(),
            ))?;
            Ok(X509Ext::from_ptr(ptr))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::x509::extensions::ToExt;

    use super::BasicConstraints;

    #[test]
    pub fn test_basic_constraints() {
        let bc = BasicConstraints::new(true, true, None);
        let bc_ext = bc.to_ext().unwrap();
        println!("OID: {}", bc_ext.get_oid());
        println!("DATA: {}", bc.to_string());
        assert_eq!("2.5.29.19", bc_ext.get_oid())
    }
}
