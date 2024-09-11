use std::fmt::Display;

use crate::{
    error::ErrorStack,
    evp::{EvpId, EvpPkey, Private},
    ossl_param::{OsslParamBld, OsslParamRef},
};

use super::{EvpCtx, KeyType, Public};

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum RsaSize {
    Rs1024 = 1024,
    Rs2048 = 2048,
    Rs4096 = 4096,
}

#[derive(Clone)]
pub struct RsaKey<KT: KeyType>(EvpPkey<KT>);

impl RsaKey<Private> {
    pub fn new_rsa(size: RsaSize) -> Result<Self, ErrorStack> {
        let ctx = EvpCtx::<Private>::from(EvpId::RsaId);
        let params = OsslParamBld::new().push_u32("bits", size as u32).build();
        Self::try_from((ctx, params.as_ref()))
    }

    pub fn new_rsa_pss(size: RsaSize) -> Result<Self, ErrorStack> {
        let ctx = EvpCtx::<Private>::from(EvpId::RsaPssId);
        let params = OsslParamBld::new().push_u32("bits", size as u32).build();
        Self::try_from((ctx, params.as_ref()))
    }

    pub fn new_rsa_with_params(params: &OsslParamRef) -> Result<Self, ErrorStack> {
        let ctx = EvpCtx::<Private>::from(EvpId::RsaId);
        Self::try_from((ctx, params))
    }

    pub fn new_rsa_pss_with_params(params: &OsslParamRef) -> Result<Self, ErrorStack> {
        let ctx = EvpCtx::<Private>::from(EvpId::RsaPssId);
        Self::try_from((ctx, params))
    }

    pub fn get_public(&self) -> Result<RsaKey<Public>, ErrorStack> {
        RsaKey::<Public>::try_from(self)
    }
}

impl TryFrom<(EvpCtx<Private>, &OsslParamRef)> for RsaKey<Private> {
    type Error = ErrorStack;

    fn try_from((ctx, params): (EvpCtx<Private>, &OsslParamRef)) -> Result<Self, Self::Error> {
        Ok(Self(EvpPkey::try_from((ctx, params))?))
    }
}

impl TryFrom<&RsaKey<Private>> for RsaKey<Public> {
    type Error = ErrorStack;

    fn try_from(value: &RsaKey<Private>) -> Result<Self, Self::Error> {
        Ok(Self(value.0.get_public()?))
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
