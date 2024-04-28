use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::ssl::*;

foreign_type! {
    pub unsafe type TsReq: Sync + Send {
        type CType = TS_REQ;
        fn drop = TS_REQ_free;
        fn clone = TS_REQ_dup;
    }
}

foreign_type! {
    pub unsafe type TsResp: Sync + Send {
        type CType = TS_RESP;
        fn drop = TS_RESP_free;
        fn clone = TS_RESP_dup;
    }
}
