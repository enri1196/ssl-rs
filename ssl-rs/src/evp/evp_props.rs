use num_derive::FromPrimitive;

use crate::{ossl_param::OsslParam, ssl::*};

pub struct Private;
pub struct Public;

pub trait KeyType {}

impl KeyType for Private {}
impl KeyType for Public {}

pub trait KeyAlgorithm {}

impl KeyAlgorithm for RsaKey {}
impl KeyAlgorithm for EcKey {}

pub type Nid = u32;

#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
#[repr(u32)]
pub enum EvpId {
    RsaId = EVP_PKEY_RSA,
    RsaPssId = EVP_PKEY_RSA_PSS,
    EcId = EVP_PKEY_EC,
    X25519Id = EVP_PKEY_X25519,
    X448Id = EVP_PKEY_X448,
    Ed25519Id = EVP_PKEY_ED25519,
    Ed448Id = EVP_PKEY_ED448,
}

impl EvpId {
    pub fn get_raw(&self) -> u32 {
        *self as u32
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EcKey(pub(crate) EvpId, pub(crate) Nid);

impl EcKey {
    pub const SECP_112R1: EcKey = EcKey(EvpId::EcId, NID_secp112r1);
    pub const SECP_112R2: EcKey = EcKey(EvpId::EcId, NID_secp112r2);
    pub const SECP_128R1: EcKey = EcKey(EvpId::EcId, NID_secp128r1);
    pub const SECP_128R2: EcKey = EcKey(EvpId::EcId, NID_secp128r2);
    pub const SECP_256K1: EcKey = EcKey(EvpId::EcId, NID_secp256k1);
    pub const SECP_521R1: EcKey = EcKey(EvpId::EcId, NID_secp521r1);
    pub const X25519: EcKey = EcKey(EvpId::X25519Id, NID_X25519);
    pub const X448: EcKey = EcKey(EvpId::X448Id, NID_X448);
    pub const ED25519: EcKey = EcKey(EvpId::Ed25519Id, NID_ED25519);
    pub const ED448: EcKey = EcKey(EvpId::Ed448Id, NID_ED448);
}

#[derive(Clone, Copy, Debug)]
pub struct RsaKey(pub(crate) EvpId, pub(crate) u32);

impl RsaKey {
    pub const RSA_1024_BITS: RsaKey = RsaKey(EvpId::RsaId, 1024);
    pub const RSA_2048_BITS: RsaKey = RsaKey(EvpId::RsaId, 2048);
    pub const RSA_4096_BITS: RsaKey = RsaKey(EvpId::RsaId, 4096);
    pub const RSA_PSS_1024_BITS: RsaKey = RsaKey(EvpId::RsaPssId, 1024);
    pub const RSA_PSS_2048_BITS: RsaKey = RsaKey(EvpId::RsaPssId, 2048);
    pub const RSA_PSS_4096_BITS: RsaKey = RsaKey(EvpId::RsaPssId, 4096);
}

#[derive(Clone)]
pub struct RsaParams(pub(crate) EvpId, pub(crate) OsslParam);

impl RsaParams {
    pub fn new_rsa(params: OsslParam) -> Self {
        Self(EvpId::RsaId, params)
    }

    pub fn new_rsa_pss(params: OsslParam) -> Self {
        Self(EvpId::RsaPssId, params)
    }
}

#[derive(Clone)]
pub struct EcParams(pub(crate) EvpId, pub(crate) OsslParam);

impl EcParams {
    pub fn new_ec(params: OsslParam) -> Self {
        Self(EvpId::EcId, params)
    }
}
