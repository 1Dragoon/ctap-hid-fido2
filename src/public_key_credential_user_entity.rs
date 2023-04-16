use crate::util;
use serde_cbor::Value;
use std::fmt;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PublicKeyCredentialUserEntity {
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: String,
}
impl PublicKeyCredentialUserEntity {
    #[must_use]
    pub fn new(id: Option<&[u8]>, name: Option<&str>, display_name: Option<&str>) -> Self {
        let mut ret = Self::default();
        if let Some(v) = id {
            ret.id = v.to_vec();
        }
        if let Some(v) = name {
            ret.name = v.to_string();
        }
        if let Some(v) = display_name {
            ret.display_name = v.to_string();
        }
        ret
    }

    #[must_use]
    pub fn get_id(&mut self, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.id = util::cbor_get_bytes_from_map(cbor, "id").unwrap_or_default();
        ret
    }

    #[must_use]
    pub fn get_name(&mut self, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.name = util::cbor_get_string_from_map(cbor, "name").unwrap_or_default();
        ret
    }

    #[must_use]
    pub fn get_display_name(&mut self, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.display_name = util::cbor_get_string_from_map(cbor, "displayName").unwrap_or_default();
        ret
    }
}
impl fmt::Display for PublicKeyCredentialUserEntity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(id : {} , name : {} , display_name : {})",
            util::to_hex_str(&self.id),
            self.name,
            self.display_name
        )
    }
}
