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

#[cfg(test)]
mod test {
    use crate::evp::{EcKey, EvpPkey, Private};

    #[test]
    pub fn test_ec() {
        let key = EvpPkey::<Private>::try_from(EcKey::SECP_256K1).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        assert_eq!(408, key.id().get_raw());
        assert_eq!(72, key.size());
    }

    #[test]
    pub fn test_ec_x25519() {
        let key = EvpPkey::<Private>::try_from(EcKey::X25519).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        assert_eq!(1034, key.id().get_raw());
        assert_eq!(32, key.size());
    }

    #[test]
    pub fn test_ec_x448() {
        let key = EvpPkey::<Private>::try_from(EcKey::X448).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        assert_eq!(1035, key.id().get_raw());
        assert_eq!(56, key.size());
    }
}
