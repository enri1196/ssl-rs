use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::ssl::*;

foreign_type! {
    pub unsafe type OcspReq: Sync + Send {
        type CType = OCSP_REQUEST;
        fn drop = OCSP_REQUEST_free;
    }
}

foreign_type! {
    pub unsafe type OcspResp: Sync + Send {
        type CType = OCSP_RESPONSE;
        fn drop = OCSP_RESPONSE_free;
    }
}
