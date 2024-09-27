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
            let code = ERR_get_error();

            if code == 0 {
                return ErrorStack {
                    code: 0,
                    reason: String::from("No error"),
                };
            }

            let bio = SslBio::memory();
            ERR_print_errors(bio.as_ptr());

            let reason = bio
                .get_data()
                .and_then(|data| String::from_utf8(data.to_vec()).ok())
                .unwrap_or_else(|| "Unknown error".to_string());

            ErrorStack { code, reason }
        }
    }
}

impl From<&'static str> for ErrorStack {
    fn from(value: &'static str) -> Self {
        Self {
            code: u64::MAX,
            reason: value.to_string(),
        }
    }
}
