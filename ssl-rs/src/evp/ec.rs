use core::str;
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
pub enum CurveNid {
    Prime256v1,
    Secp112r1,
    Secp112r2,
    Secp128r1,
    Secp128r2,
    Secp160k1,
    Secp160r1,
    Secp160r2,
    Secp192k1,
    Secp224k1,
    Secp224r1,
    Secp256k1,
    Secp384r1,
    Secp521r1,
    Sect113r1,
    Sect113r2,
    Sect131r1,
    Sect131r2,
    Sect163k1,
    Sect163r1,
    Sect163r2,
    Sect193r1,
    Sect193r2,
    Sect233k1,
    Sect233r1,
    Sect239k1,
    Sect283k1,
    Sect283r1,
    Sect409k1,
    Sect409r1,
    Sect571k1,
    Sect571r1,
}

impl CurveNid {
    pub const fn as_str(&self) -> &'static str {
        // SAFETY: all the Cstrings are compile time constants known to be safe
        unsafe { self.inner_as_str() }
    }

    const unsafe fn inner_as_str(&self) -> &'static str {
        match self {
            Self::Prime256v1 => std::str::from_utf8_unchecked(SN_X9_62_prime256v1.to_bytes()),
            Self::Secp112r1 => std::str::from_utf8_unchecked(SN_secp112r1.to_bytes()),
            Self::Secp112r2 => std::str::from_utf8_unchecked(SN_secp112r2.to_bytes()),
            Self::Secp128r1 => std::str::from_utf8_unchecked(SN_secp128r1.to_bytes()),
            Self::Secp128r2 => std::str::from_utf8_unchecked(SN_secp128r2.to_bytes()),
            Self::Secp160k1 => std::str::from_utf8_unchecked(SN_secp160k1.to_bytes()),
            Self::Secp160r1 => std::str::from_utf8_unchecked(SN_secp160r1.to_bytes()),
            Self::Secp160r2 => std::str::from_utf8_unchecked(SN_secp160r2.to_bytes()),
            Self::Secp192k1 => std::str::from_utf8_unchecked(SN_secp192k1.to_bytes()),
            Self::Secp224k1 => std::str::from_utf8_unchecked(SN_secp224k1.to_bytes()),
            Self::Secp224r1 => std::str::from_utf8_unchecked(SN_secp224r1.to_bytes()),
            Self::Secp256k1 => std::str::from_utf8_unchecked(SN_secp256k1.to_bytes()),
            Self::Secp384r1 => std::str::from_utf8_unchecked(SN_secp384r1.to_bytes()),
            Self::Secp521r1 => std::str::from_utf8_unchecked(SN_secp521r1.to_bytes()),
            Self::Sect113r1 => std::str::from_utf8_unchecked(SN_sect113r1.to_bytes()),
            Self::Sect113r2 => std::str::from_utf8_unchecked(SN_sect113r2.to_bytes()),
            Self::Sect131r1 => std::str::from_utf8_unchecked(SN_sect131r1.to_bytes()),
            Self::Sect131r2 => std::str::from_utf8_unchecked(SN_sect131r2.to_bytes()),
            Self::Sect163k1 => std::str::from_utf8_unchecked(SN_sect163k1.to_bytes()),
            Self::Sect163r1 => std::str::from_utf8_unchecked(SN_sect163r1.to_bytes()),
            Self::Sect163r2 => std::str::from_utf8_unchecked(SN_sect163r2.to_bytes()),
            Self::Sect193r1 => std::str::from_utf8_unchecked(SN_sect193r1.to_bytes()),
            Self::Sect193r2 => std::str::from_utf8_unchecked(SN_sect193r2.to_bytes()),
            Self::Sect233k1 => std::str::from_utf8_unchecked(SN_sect233k1.to_bytes()),
            Self::Sect233r1 => std::str::from_utf8_unchecked(SN_sect233r1.to_bytes()),
            Self::Sect239k1 => std::str::from_utf8_unchecked(SN_sect239k1.to_bytes()),
            Self::Sect283k1 => std::str::from_utf8_unchecked(SN_sect283k1.to_bytes()),
            Self::Sect283r1 => std::str::from_utf8_unchecked(SN_sect283r1.to_bytes()),
            Self::Sect409k1 => std::str::from_utf8_unchecked(SN_sect409k1.to_bytes()),
            Self::Sect409r1 => std::str::from_utf8_unchecked(SN_sect409r1.to_bytes()),
            Self::Sect571k1 => std::str::from_utf8_unchecked(SN_sect571k1.to_bytes()),
            Self::Sect571r1 => std::str::from_utf8_unchecked(SN_sect571r1.to_bytes()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum CurveRawNid {
    X25519 = NID_X25519,
    X448 = NID_X448,
    ED25519 = NID_ED25519,
    ED448 = NID_ED448,
}

impl CurveRawNid {
    pub const fn as_str(&self) -> &'static str {
        // SAFETY: all the Cstrings are compile time constants known to be safe
        unsafe { self.inner_as_str() }
    }

    const unsafe fn inner_as_str(&self) -> &'static str {
        match self {
            CurveRawNid::X25519 => std::str::from_utf8_unchecked(SN_X25519.to_bytes()),
            CurveRawNid::X448 => std::str::from_utf8_unchecked(SN_X448.to_bytes()),
            CurveRawNid::ED25519 => std::str::from_utf8_unchecked(SN_ED25519.to_bytes()),
            CurveRawNid::ED448 => std::str::from_utf8_unchecked(SN_ED448.to_bytes()),
        }
    }

    fn to_evp_id(self) -> EvpId {
        match self {
            CurveRawNid::X25519 => EvpId::X25519Id,
            CurveRawNid::X448 => EvpId::X448Id,
            CurveRawNid::ED25519 => EvpId::Ed25519Id,
            CurveRawNid::ED448 => EvpId::Ed448Id,
        }
    }

    pub(crate) fn raw_key_type(&self) -> RawKeyType {
        match self {
            CurveRawNid::X25519 | CurveRawNid::X448 => RawKeyType::KeyExchange,
            CurveRawNid::ED25519 | CurveRawNid::ED448 => RawKeyType::Signature,
        }
    }
}

// Define KeyType to distinguish key purposes
#[derive(Debug, Clone, Copy)]
pub(crate) enum RawKeyType {
    KeyExchange,
    Signature,
}

#[derive(Clone)]
pub struct EcKey<KT: KeyType>(EvpPkey<KT>);

impl<KT: KeyType> AsRef<EvpPkeyRef<KT>> for EcKey<KT> {
    fn as_ref(&self) -> &EvpPkeyRef<KT> {
        &self.0
    }
}

impl EcKey<Private> {
    pub fn new_ec(curve: CurveNid) -> Result<Self, ErrorStack> {
        let ctx = EvpCtx::from(EvpId::EcId);
        let key = std::str::from_utf8(OSSL_PKEY_PARAM_GROUP_NAME.to_bytes()).unwrap();
        let params = OsslParamBld::new().push_str(key, curve.as_str()).build();
        Self::try_from((ctx, params.as_ref()))
    }

    pub fn new_raw_ec(curve: CurveRawNid) -> Result<Self, ErrorStack> {
        match curve.raw_key_type() {
            RawKeyType::KeyExchange => Self::generate_key_exchange(curve),
            RawKeyType::Signature => Self::generate_key_signature(curve),
        }
    }

    fn generate_key_exchange(curve: CurveRawNid) -> Result<Self, ErrorStack> {
        let ctx = EvpCtx::from(curve.to_evp_id());
        let key = std::str::from_utf8(OSSL_PKEY_PARAM_GROUP_NAME.to_bytes()).unwrap();
        let params = OsslParamBld::new().push_str(key, curve.as_str()).build();
        Self::try_from((ctx, params.as_ref()))
    }

    fn generate_key_signature(curve: CurveRawNid) -> Result<Self, ErrorStack> {
        let ctx = EvpCtx::from(curve.to_evp_id());
        Self::try_from(ctx)
    }

    pub fn get_public(&self) -> Result<EcKey<Public>, ErrorStack> {
        EcKey::<Public>::try_from(self)
    }

    pub fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        self.0.sign(tbs)
    }
}

impl Signer<Vec<u8>> for EcKey<Private> {
    fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        self.0.as_ref().try_sign(msg)
    }
}

impl EcKey<Public> {
    pub fn verify_sign(&self, tbs: &[u8], signature: &[u8]) -> Result<bool, ErrorStack> {
        self.0.verify_sign(tbs, signature)
    }
}

impl Verifier<Vec<u8>> for EcKey<Public> {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> Result<(), signature::Error> {
        self.0.as_ref().verify(msg, signature)
    }
}

impl TryFrom<EvpCtx> for EcKey<Private> {
    type Error = ErrorStack;

    fn try_from(ctx: EvpCtx) -> Result<Self, Self::Error> {
        EvpPkey::try_from(ctx).map(Self)
    }
}

impl TryFrom<(EvpCtx, &OsslParamRef)> for EcKey<Private> {
    type Error = ErrorStack;

    fn try_from((ctx, params): (EvpCtx, &OsslParamRef)) -> Result<Self, Self::Error> {
        EvpPkey::try_from((ctx, params)).map(Self)
    }
}

impl TryFrom<&EcKey<Private>> for EcKey<Public> {
    type Error = ErrorStack;

    fn try_from(value: &EcKey<Private>) -> Result<Self, Self::Error> {
        value.0.get_public().map(Self)
    }
}

impl From<EcKey<Private>> for EvpPkey<Private> {
    fn from(value: EcKey<Private>) -> Self {
        value.0
    }
}

impl From<EcKey<Public>> for EvpPkey<Public> {
    fn from(value: EcKey<Public>) -> Self {
        value.0
    }
}

impl Display for EcKey<Private> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_ref())
    }
}

impl Display for EcKey<Public> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_ref())
    }
}
