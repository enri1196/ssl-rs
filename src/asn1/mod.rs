mod asn1_integer;
mod asn1_string;
mod asn1_time;
mod general_name;

use crate::ssl::*;

pub use asn1_integer::*;
pub use asn1_time::*;
use num_derive::FromPrimitive;

#[derive(Debug, Clone, Copy, FromPrimitive)]
#[repr(u32)]
pub enum Asn1Type {
    Eoc = V_ASN1_EOC,
    Boolean = V_ASN1_BOOLEAN,
    Integer = V_ASN1_INTEGER,
    BitString = V_ASN1_BIT_STRING,
    OctetString = V_ASN1_OCTET_STRING,
    Null = V_ASN1_NULL,
    Object = V_ASN1_OBJECT,
    ObjectDescriptor = V_ASN1_OBJECT_DESCRIPTOR,
    External = V_ASN1_EXTERNAL,
    Real = V_ASN1_REAL,
    Enumerated = V_ASN1_ENUMERATED,
    Utf8String = V_ASN1_UTF8STRING,
    Sequence = V_ASN1_SEQUENCE,
    Set = V_ASN1_SET,
    NumericString = V_ASN1_NUMERICSTRING,
    PrintableString = V_ASN1_PRINTABLESTRING,
    // T61String = V_ASN1_T61STRING,
    // TeletexString = V_ASN1_TELETEXSTRING,
    VideotexString = V_ASN1_VIDEOTEXSTRING,
    Ia5String = V_ASN1_IA5STRING,
    UtcTime = V_ASN1_UTCTIME,
    GeneralizedTime = V_ASN1_GENERALIZEDTIME,
    GraphicString = V_ASN1_GRAPHICSTRING,
    // Iso64String = V_ASN1_ISO64STRING,
    // VisibleString = V_ASN1_VISIBLESTRING,
    GeneralString = V_ASN1_GENERALSTRING,
    UniverslString = V_ASN1_UNIVERSALSTRING,
    BmpString = V_ASN1_BMPSTRING,
}
