use foreign_types::{ForeignType, ForeignTypeRef};

use crate::{
    error::ErrorStack, evp::{EcKey, EvpPkey, Private}, ossl_param::OsslParamRef, ssl::*
};

use super::{EvpCtx, KeyGen, ParamsKeyGen};

impl KeyGen<EcKey> for EvpCtx<Private> {
    fn generate(self, alg: EcKey) -> Result<EvpPkey<Private>, ErrorStack> {
        unsafe {
            let EcKey(_, nid) = alg;
            let m_key = EvpPkey::default();
            EVP_PKEY_keygen_init(self.as_ptr());
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(self.as_ptr(), nid as i32);

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
            let m_key = EvpPkey::<Private>::default();
            crate::check_code(EVP_PKEY_keygen_init(self.as_ptr()))?;
            crate::check_code(EVP_PKEY_CTX_set_params(
                self.as_ptr(),
                params.as_ptr() as *const _,
            ))?;
            EVP_PKEY_generate(self.as_ptr(), &mut m_key.as_ptr() as *mut *mut _);
            Ok(m_key)
        }
    }
}

