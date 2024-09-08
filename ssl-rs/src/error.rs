use foreign_types::ForeignType;
use thiserror::Error;

use crate::{bio::SslBio, ssl::*};

#[derive(Debug, Error)]
#[error("SslErr {code}: {reason}")]
pub struct ErrorStack {
    code: u64,
    reason: String,
}

impl ErrorStack {
    pub fn get() -> ErrorStack {
        unsafe {
            let bio = SslBio::memory();
            ERR_print_errors(bio.as_ptr());
            ErrorStack {
                code: ERR_get_error(),
                reason: String::from_utf8(bio.get_data().to_vec()).unwrap_or_default(),
            }
        }
    }
}
