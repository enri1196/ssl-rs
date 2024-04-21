use crate::ssl::*;

pub struct Private;
pub struct Public;

pub trait KeyType {}

impl KeyType for Private {}
impl KeyType for Public {}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EvpId(u32);

impl EvpId {
    pub fn get_raw(&self) -> u32 {
        self.0
    }
}

impl From<u32> for EvpId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

pub const RSA_ID: EvpId = EvpId(EVP_PKEY_RSA);
pub const RSA_PSS_ID: EvpId = EvpId(EVP_PKEY_RSA_PSS);
pub const EC_ID: EvpId = EvpId(EVP_PKEY_EC);
pub const DSA_ID: EvpId = EvpId(EVP_PKEY_DSA);
pub const DH_ID: EvpId = EvpId(EVP_PKEY_DH);
pub const X25519_ID: EvpId = EvpId(EVP_PKEY_X25519);
pub const X448_ID: EvpId = EvpId(EVP_PKEY_X448);
pub const ED25519_ID: EvpId = EvpId(EVP_PKEY_ED25519);
pub const ED448_ID: EvpId = EvpId(EVP_PKEY_ED448);

#[derive(Clone, Copy, Debug)]
pub struct EcKey(pub(crate) EvpId, pub(crate) u32);

impl EcKey {
    pub const SECP_112R1: EcKey = EcKey(EC_ID, NID_secp112r1);
    pub const SECP_112R2: EcKey = EcKey(EC_ID, NID_secp112r2);
    pub const SECP_128R1: EcKey = EcKey(EC_ID, NID_secp128r1);
    pub const SECP_128R2: EcKey = EcKey(EC_ID, NID_secp128r2);
    pub const SECP_256K1: EcKey = EcKey(EC_ID, NID_secp256k1);
    pub const SECP_521R1: EcKey = EcKey(EC_ID, NID_secp521r1);
    pub const X25519: EcKey = EcKey(X25519_ID, NID_X25519);
    pub const X448: EcKey = EcKey(X448_ID, NID_X448);
    pub const ED25519: EcKey = EcKey(ED25519_ID, NID_ED25519);
    pub const ED448: EcKey = EcKey(ED448_ID, NID_ED448);
}

#[derive(Clone, Copy, Debug)]
pub struct RsaKey(pub(crate) EvpId, pub(crate) u32);

impl RsaKey {
    pub const RSA_1024_BITS: RsaKey = RsaKey(RSA_ID, 1024);
    pub const RSA_2048_BITS: RsaKey = RsaKey(RSA_ID, 2048);
    pub const RSA_4096_BITS: RsaKey = RsaKey(RSA_ID, 4096);
}

#[derive(Clone, Copy, Debug)]
pub struct DsaKey(pub(crate) EvpId, pub(crate) u32);

impl DsaKey {
    pub const DSA_2048_BITS: DsaKey = DsaKey(DSA_ID, 2048);
}

pub trait KeyAlgorithm {}

impl KeyAlgorithm for RsaKey {}
impl KeyAlgorithm for EcKey {}
impl KeyAlgorithm for DsaKey {}
