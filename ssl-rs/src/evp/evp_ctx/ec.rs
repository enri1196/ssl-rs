use foreign_types::ForeignType;

use crate::{
    error::ErrorStack,
    evp::{EcKey, EvpPkey, Private},
    ssl::*,
};

use super::{EvpCtx, KeyGen};

impl KeyGen<EcKey> for EvpCtx<Private, EcKey> {
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
