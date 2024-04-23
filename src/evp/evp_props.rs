use crate::ssl::*;

pub struct Private;
pub struct Public;

pub trait KeyType {}

impl KeyType for Private {}
impl KeyType for Public {}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum EvpId {
    RsaId = EVP_PKEY_RSA,
    RsaPssId = EVP_PKEY_RSA_PSS,
    EcId = EVP_PKEY_EC,
    DsaId = EVP_PKEY_DSA,
    DhId = EVP_PKEY_DH,
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

impl From<u32> for EvpId {
    fn from(value: u32) -> Self {
        match value {
            EVP_PKEY_RSA => EvpId::RsaId, 
            EVP_PKEY_RSA_PSS => EvpId::RsaPssId, 
            EVP_PKEY_EC => EvpId::EcId, 
            EVP_PKEY_DSA => EvpId::DsaId, 
            EVP_PKEY_DH => EvpId::DhId, 
            EVP_PKEY_X25519 => EvpId::X25519Id, 
            EVP_PKEY_X448 => EvpId::X448Id, 
            EVP_PKEY_ED25519 => EvpId::Ed25519Id, 
            EVP_PKEY_ED448 => EvpId::Ed448Id, 
            _ => unreachable!()
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EcKey(pub(crate) EvpId, pub(crate) u32);

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
}

#[derive(Clone, Copy, Debug)]
pub struct DsaKey(pub(crate) EvpId, pub(crate) u32);

impl DsaKey {
    pub const DSA_1024_BITS: DsaKey = DsaKey(EvpId::DsaId, 1024);
    pub const DSA_2048_BITS: DsaKey = DsaKey(EvpId::DsaId, 2048);
    pub const DSA_4096_BITS: DsaKey = DsaKey(EvpId::DsaId, 4096);
}

pub trait KeyAlgorithm {}

impl KeyAlgorithm for RsaKey {}
impl KeyAlgorithm for EcKey {}
impl KeyAlgorithm for DsaKey {}
