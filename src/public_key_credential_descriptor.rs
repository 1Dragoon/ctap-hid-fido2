use crate::util;
use serde_cbor::Value;
use std::fmt;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PublicKeyCredentialDescriptor {
    pub id: Vec<u8>,
    pub ctype: String,
}
impl PublicKeyCredentialDescriptor {
    #[must_use]
    pub fn get_id(&mut self, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.id = util::cbor_get_bytes_from_map(cbor, "id").unwrap_or_default();
        ret
    }

    #[must_use]
    pub fn get_type(&mut self, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.ctype = util::cbor_get_string_from_map(cbor, "type").unwrap_or_default();
        ret
    }
}
impl fmt::Display for PublicKeyCredentialDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(id : {} , type : {})",
            util::to_hex_str(&self.id),
            self.ctype
        )
    }
}
