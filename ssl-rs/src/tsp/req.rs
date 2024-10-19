use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::{
    asn1::{Asn1IntegerRef, Asn1ObjectRef, Asn1OctetStringRef},
    error::ErrorStack,
    ssl::*,
    x509::{X509AlgRef, X509ExtRef},
};

foreign_type! {
    pub unsafe type TsReq: Sync + Send {
        type CType = TS_REQ;
        fn drop = TS_REQ_free;
        fn clone = TS_REQ_dup;
    }
}

impl TsReqRef {
    pub fn get_version(&self) -> i64 {
        unsafe { TS_REQ_get_version(self.as_ptr()) }
    }

    pub fn get_msg_imprint(&self) -> &TsMsgImprintRef {
        unsafe { TsMsgImprintRef::from_ptr(TS_REQ_get_msg_imprint(self.as_ptr())) }
    }

    pub fn get_req_policy(&self) -> Option<&TsaPolicyId> {
        unsafe {
            let ptr = TS_REQ_get_policy_id(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(TsaPolicyId::from_ptr(ptr))
            }
        }
    }

    pub fn get_nonce(&self) -> Option<&Asn1IntegerRef> {
        unsafe {
            let ptr = TS_REQ_get_nonce(self.as_ptr()) as *mut ASN1_INTEGER;
            if ptr.is_null() {
                None
            } else {
                Some(Asn1IntegerRef::from_ptr(ptr))
            }
        }
    }

    pub fn get_cert_req(&self) -> bool {
        unsafe { TS_REQ_get_cert_req(self.as_ptr()) == 1 }
    }

    pub fn get_ext(&self, idx: i32) -> Option<&X509ExtRef> {
        unsafe {
            let ptr = TS_REQ_get_ext(self.as_ptr(), idx);
            if ptr.is_null() {
                None
            } else {
                Some(X509ExtRef::from_ptr(ptr))
            }
        }
    }

    pub fn get_ext_len(&self) -> usize {
        unsafe { TS_REQ_get_ext_count(self.as_ptr()) as usize }
    }
}

impl TryFrom<&[u8]> for TsReq {
    type Error = ErrorStack;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        unsafe {
            let ptr = crate::check_ptr(d2i_TS_REQ(
                std::ptr::null_mut(),
                value.as_ptr() as *mut *const _,
                value.len() as i64,
            ))?;
            Ok(Self::from_ptr(ptr))
        }
    }
}

foreign_type! {
    pub unsafe type TsMsgImprint: Sync + Send {
        type CType = TS_MSG_IMPRINT;
        fn drop = TS_MSG_IMPRINT_free;
        fn clone = TS_MSG_IMPRINT_dup;
    }
}

impl TsMsgImprintRef {
    pub fn get_hash_algorithm(&self) -> &X509AlgRef {
        unsafe { X509AlgRef::from_ptr(TS_MSG_IMPRINT_get_algo(self.as_ptr())) }
    }

    pub fn get_hashed_msg(&self) -> &Asn1OctetStringRef {
        unsafe { Asn1OctetStringRef::from_ptr(TS_MSG_IMPRINT_get_msg(self.as_ptr())) }
    }
}

type TsaPolicyId = Asn1ObjectRef;

pub struct TsReqBuilder {
    version: Option<i64>,
    msg_imprint: Option<TsMsgImprint>,
    req_policy: Option<TsaPolicyId>,
    nonce: Option<Asn1IntegerRef>,
    cert_req: Option<bool>,
    extensions: Vec<X509ExtRef>,
}

impl TsReqBuilder {
    pub fn new() -> Self {
        Self {
            version: None,
            msg_imprint: None,
            req_policy: None,
            nonce: None,
            cert_req: None,
            extensions: Vec::new(),
        }
    }

    pub fn version(mut self, version: i64) -> Self {
        self.version = Some(version);
        self
    }

    pub fn msg_imprint(mut self, msg_imprint: TsMsgImprint) -> Self {
        self.msg_imprint = Some(msg_imprint);
        self
    }

    pub fn req_policy(mut self, policy_id: TsaPolicyId) -> Self {
        self.req_policy = Some(policy_id);
        self
    }

    pub fn nonce(mut self, nonce: &Asn1IntegerRef) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn cert_req(mut self, cert_req: bool) -> Self {
        self.cert_req = Some(cert_req);
        self
    }

    pub fn add_extension(mut self, ext: X509ExtRef) -> Self {
        self.extensions.push(ext);
        self
    }

    pub fn build(self) -> Result<TsReq, ErrorStack> {
        // Safety checks and conversions based on provided values
        let version = self.version.unwrap_or(1); // default version
        let msg_imprint = self
            .msg_imprint
            .ok_or_else(|| ErrorStack::get())?; // msg_imprint is mandatory
        let cert_req = self.cert_req.unwrap_or(false);

        // Create new TS_REQ structure
        unsafe {
            let req = TsReq::from_ptr(crate::check_ptr(TS_REQ_new())?);

            // Set version
            TS_REQ_set_version(req.as_ptr(), version);

            // Set msg_imprint
            TS_REQ_set_msg_imprint(req.as_ptr(), msg_imprint.as_ptr());

            // Set optional policy
            if let Some(policy_id) = self.req_policy {
                TS_REQ_set_policy_id(req.as_ptr(), policy_id.as_ptr());
            }

            // Set optional nonce
            if let Some(nonce) = self.nonce {
                TS_REQ_set_nonce(req.as_ptr(), nonce.as_ptr());
            }

            // Set cert_req
            TS_REQ_set_cert_req(req.as_ptr(), cert_req as i32);

            // Add extensions if any
            for (i, ext) in self.extensions.into_iter().enumerate() {
                TS_REQ_add_ext(req.as_ptr(), ext.as_ptr(), i as i32);
            }

            Ok(req)
        }
    }
}
