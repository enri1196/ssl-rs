use core::str;
use std::fmt::Display;

use crate::{
    error::ErrorStack,
    evp::{EvpCtx, EvpId, EvpPkey, KeyType, Private, Public},
    ossl_param::{OsslParamBld, OsslParamRef},
    ssl::*,
};

#[derive(Debug, Clone, Copy)]
pub enum CurveNid {
    // Secp112r1,
    // Secp112r2,
    // Secp128r1,
    // Secp521r1,
    // Secp128r2,
    Prime256v1,
    Secp521r1,
    Secp256k1,
    // X25519 = NID_X25519,
    // X448 = NID_X448,
    // ED25519 = NID_ED25519,
    // ED448 = NID_ED448,
}

impl CurveNid {
    pub const fn as_str(&self) -> &'static str {
        unsafe {
            match self {
                // CurveNid::Secp112r1 => {
                //     std::str::from_raw_parts(SN_secp112r1.as_ptr(), SN_secp112r1.len())
                // }
                // CurveNid::Secp112r2 => {
                //     std::str::from_raw_parts(SN_secp112r2.as_ptr(), SN_secp112r2.len())
                // }
                // CurveNid::Secp128r1 => {
                //     std::str::from_raw_parts(SN_secp128r1.as_ptr(), SN_secp128r1.len())
                // }
                // CurveNid::Secp521r1 => {
                //     std::str::from_raw_parts(SN_secp521r1.as_ptr(), SN_secp521r1.len())
                // }
                // CurveNid::Secp128r2 => {
                //     std::str::from_raw_parts(SN_secp128r2.as_ptr(), SN_secp128r2.len())
                // }
                CurveNid::Prime256v1 => {
                    std::str::from_utf8_unchecked(SN_X9_62_prime256v1.as_slice())
                }
                CurveNid::Secp521r1 => std::str::from_utf8_unchecked(SN_secp521r1.as_slice()),
                CurveNid::Secp256k1 => std::str::from_utf8_unchecked(SN_secp256k1.as_slice()),
            }
        }
    }
}

#[derive(Clone)]
pub struct EcKey<KT: KeyType>(EvpPkey<KT>);

impl EcKey<Private> {
    pub fn new_ec(curve: CurveNid) -> Result<Self, ErrorStack> {
        let ctx = EvpCtx::<Private>::from(EvpId::EcId);
        let key = std::str::from_utf8(OSSL_PKEY_PARAM_GROUP_NAME.as_slice()).unwrap();
        let params = OsslParamBld::new()
            .push_str(key, curve.as_str())
            .build();
        Self::try_from((ctx, params.as_ref()))
    }

    pub fn get_public(&self) -> Result<EcKey<Public>, ErrorStack> {
        EcKey::<Public>::try_from(self)
    }
}

impl TryFrom<(EvpCtx<Private>, &OsslParamRef)> for EcKey<Private> {
    type Error = ErrorStack;

    fn try_from((ctx, params): (EvpCtx<Private>, &OsslParamRef)) -> Result<Self, Self::Error> {
        EvpPkey::try_from((ctx, params)).map(Self)
    }
}

impl TryFrom<&EcKey<Private>> for EcKey<Public> {
    type Error = ErrorStack;

    fn try_from(value: &EcKey<Private>) -> Result<Self, Self::Error> {
        value.0.get_public().map(Self)
    }
}

impl Display for EcKey<Private> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_string())
    }
}

impl Display for EcKey<Public> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_string())
    }
}
