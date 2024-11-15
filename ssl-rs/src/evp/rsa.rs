use std::fmt::Display;

use signature::{Signer, Verifier};

use crate::{
    error::ErrorStack,
    evp::{EvpCtx, EvpId, EvpPkey, KeyType, Private, Public},
    ossl_param::{OsslParamBld, OsslParamRef},
    ssl::*,
};

use super::EvpPkeyRef;

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum RsaSize {
    Rs1024 = 1024,
    Rs2048 = 2048,
    Rs4096 = 4096,
}

#[derive(Clone)]
pub struct RsaKey<KT: KeyType>(EvpPkey<KT>);

impl<KT: KeyType> AsRef<EvpPkeyRef<KT>> for RsaKey<KT> {
    fn as_ref(&self) -> &EvpPkeyRef<KT> {
        &self.0
    }
}

impl RsaKey<Private> {
    pub fn new_rsa(size: RsaSize) -> Result<Self, ErrorStack> {
        let ctx = EvpCtx::from(EvpId::RsaId);
        let bits = std::str::from_utf8(OSSL_PKEY_PARAM_RSA_BITS.to_bytes()).unwrap();
        let params = OsslParamBld::new().push_u32(bits, size as u32).build();
        Self::try_from((ctx, params.as_ref()))
    }

    pub fn new_rsa_pss(size: RsaSize) -> Result<Self, ErrorStack> {
        let ctx = EvpCtx::from(EvpId::RsaPssId);
        let bits = std::str::from_utf8(OSSL_PKEY_PARAM_RSA_BITS.to_bytes()).unwrap();
        let params = OsslParamBld::new().push_u32(bits, size as u32).build();
        Self::try_from((ctx, params.as_ref()))
    }

    pub fn new_rsa_with_params(params: &OsslParamRef) -> Result<Self, ErrorStack> {
        let ctx = EvpCtx::from(EvpId::RsaId);
        Self::try_from((ctx, params))
    }

    pub fn new_rsa_pss_with_params(params: &OsslParamRef) -> Result<Self, ErrorStack> {
        let ctx = EvpCtx::from(EvpId::RsaPssId);
        Self::try_from((ctx, params))
    }

    pub fn get_public(&self) -> Result<RsaKey<Public>, ErrorStack> {
        RsaKey::<Public>::try_from(self)
    }

    pub fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        self.0.sign(tbs)
    }
}

impl Signer<Vec<u8>> for RsaKey<Private> {
    fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        self.0.as_ref().try_sign(msg)
    }
}

impl RsaKey<Public> {
    pub fn verify_sign(&self, tbs: &[u8], signature: &[u8]) -> Result<bool, ErrorStack> {
        self.0.verify_sign(tbs, signature)
    }
}

impl Verifier<Vec<u8>> for RsaKey<Public> {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> Result<(), signature::Error> {
        self.0.as_ref().verify(msg, signature)
    }
}

impl TryFrom<(EvpCtx, &OsslParamRef)> for RsaKey<Private> {
    type Error = ErrorStack;

    fn try_from((ctx, params): (EvpCtx, &OsslParamRef)) -> Result<Self, Self::Error> {
        EvpPkey::try_from((ctx, params)).map(Self)
    }
}

impl TryFrom<&RsaKey<Private>> for RsaKey<Public> {
    type Error = ErrorStack;

    fn try_from(value: &RsaKey<Private>) -> Result<Self, Self::Error> {
        value.0.get_public().map(Self)
    }
}

impl From<RsaKey<Private>> for EvpPkey<Private> {
    fn from(value: RsaKey<Private>) -> Self {
        value.0
    }
}

impl From<RsaKey<Public>> for EvpPkey<Public> {
    fn from(value: RsaKey<Public>) -> Self {
        value.0
    }
}

impl Display for RsaKey<Private> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_ref())
    }
}

impl Display for RsaKey<Public> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_ref())
    }
}
