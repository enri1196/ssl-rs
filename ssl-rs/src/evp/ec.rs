use foreign_types::{ForeignType, ForeignTypeRef};

use crate::{
    error::ErrorStack,
    evp::{EvpId, EvpPkey, KeyAlgorithm, Private},
    ossl_param::OsslParamRef,
    ssl::*,
};

use super::{EvpCtx, KeyGen, ParamsKeyGen};

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum CurveNid {
    Secp112r1 = NID_secp112r1,
    Secp112r2 = NID_secp112r2,
    Secp128r1 = NID_secp128r1,
    Secp521r1 = NID_secp521r1,
    Secp128r2 = NID_secp128r2,
    Secp256k1 = NID_secp256k1,
    X25519 = NID_X25519,
    X448 = NID_X448,
    ED25519 = NID_ED25519,
    ED448 = NID_ED448,
}

#[derive(Clone, Copy, Debug)]
pub struct EcKey(pub(crate) EvpId, pub(crate) CurveNid);

impl EcKey {
    pub const SECP_112R1: EcKey = EcKey(EvpId::EcId, CurveNid::Secp112r1);
    pub const SECP_112R2: EcKey = EcKey(EvpId::EcId, CurveNid::Secp112r2);
    pub const SECP_128R1: EcKey = EcKey(EvpId::EcId, CurveNid::Secp128r1);
    pub const SECP_128R2: EcKey = EcKey(EvpId::EcId, CurveNid::Secp128r2);
    pub const SECP_256K1: EcKey = EcKey(EvpId::EcId, CurveNid::Secp256k1);
    pub const SECP_521R1: EcKey = EcKey(EvpId::EcId, CurveNid::Secp521r1);
    pub const X25519: EcKey = EcKey(EvpId::X25519Id, CurveNid::X25519);
    pub const X448: EcKey = EcKey(EvpId::X448Id, CurveNid::X448);
    pub const ED25519: EcKey = EcKey(EvpId::Ed25519Id, CurveNid::ED25519);
    pub const ED448: EcKey = EcKey(EvpId::Ed448Id, CurveNid::ED448);
}

impl KeyAlgorithm for EcKey {}

impl KeyGen<EcKey> for EvpCtx<Private> {
    fn generate(self, alg: EcKey) -> Result<EvpPkey<Private>, ErrorStack> {
        unsafe {
            let EcKey(_, nid) = alg;
            let m_key = EvpPkey::default();
            crate::check_code(EVP_PKEY_keygen_init(self.as_ptr()))?;
            crate::check_code(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                self.as_ptr(),
                nid as i32,
            ))?;
            crate::check_code(EVP_PKEY_keygen(
                self.as_ptr(),
                &mut m_key.as_ptr() as *mut *mut _,
            ))?;
            Ok(m_key)
        }
    }
}

impl ParamsKeyGen<EcKey> for EvpCtx<Private> {
    fn generate_with_params(self, params: &OsslParamRef) -> Result<EvpPkey<Private>, ErrorStack> {
        unsafe {
            let m_key = EvpPkey::default();
            crate::check_code(EVP_PKEY_keygen_init(self.as_ptr()))?;
            crate::check_code(EVP_PKEY_CTX_set_params(
                self.as_ptr(),
                params.as_ptr() as *const _,
            ))?;
            crate::check_code(EVP_PKEY_generate(
                self.as_ptr(),
                &mut m_key.as_ptr() as *mut *mut _,
            ))?;
            Ok(m_key)
        }
    }
}
