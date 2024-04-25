use foreign_types::ForeignType;

use crate::{ssl::*, x509::X509Ext};

use super::{ToExt, X509ExtNid};

/// An extension which indicates whether a certificate is a CA certificate.
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

    pub fn to_value(&self) -> String {
        let mut value = String::new();
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
        value
    }
}

impl ToExt for BasicConstraints {
    fn to_ext(&self) -> X509Ext {
        unsafe {
            let ctx = std::ptr::null_mut();
            X509V3_set_ctx(
                ctx,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            );

            X509Ext::from_ptr(X509V3_EXT_conf_nid(
                std::ptr::null_mut(),
                ctx,
                X509ExtNid::BASIC_CONSTRAINTS.nid(),
                self.to_value().as_ptr(),
            ))
        }
    }
}
