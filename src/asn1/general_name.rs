use foreign_types::{foreign_type, ForeignType};

use crate::{asn1::asn1_string::Asn1String, ssl::*};

use super::Asn1Type;

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum GenNameType {
    Othername = GEN_OTHERNAME,
    Email = GEN_EMAIL,
    Dns = GEN_DNS,
    X400 = GEN_X400,
    Dirname = GEN_DIRNAME,
    Ediparty = GEN_EDIPARTY,
    Uri = GEN_URI,
    Ipadd = GEN_IPADD,
    Rid = GEN_RID,
}

foreign_type! {
    pub unsafe type GeneralName: Sync + Send {
        type CType = GENERAL_NAME;
        fn drop = GENERAL_NAME_free;
        fn clone = GENERAL_NAME_dup;
    }
}

impl GeneralName {
    fn _new(gen_type: GenNameType, asn1_type: Asn1Type, data: &str) -> Self {
        unsafe {
            let gn = Self::from_ptr(GENERAL_NAME_new());
            (*gn.as_ptr()).type_ = gen_type as i32;
            let data = Asn1String::new(asn1_type, data.as_bytes());
            GENERAL_NAME_set0_value(gn.as_ptr(), asn1_type as i32, data.as_ptr() as *mut _);

            gn
        }
    }
}
