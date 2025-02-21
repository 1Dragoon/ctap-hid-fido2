use crate::auth_data::Flags;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::str_buf::StrBuf;
use ring::digest;
use std::convert::TryFrom;
use std::fmt;
use strum_macros::AsRefStr;

/// Assertion Object
#[derive(Debug, Default, Clone)]
pub struct Assertion {
    pub rpid_hash: Vec<u8>,
    pub flags: Flags,
    pub sign_count: u32,
    pub number_of_credentials: i32,
    pub signature: Vec<u8>,
    pub user: PublicKeyCredentialUserEntity,
    pub credential_id: Vec<u8>,
    pub extensions: Vec<Extension>,
    // row - audh_data
    pub auth_data: Vec<u8>,
    pub user_selected: bool,
}

impl fmt::Display for Assertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strbuf = StrBuf::new(42);
        strbuf
            .appenh("- rpid_hash", &self.rpid_hash)
            .append("- sign_count", &self.sign_count)
            .add(&format!("{}", &self.flags))
            .append("- number_of_credentials", &self.number_of_credentials)
            .appenh("- signature", &self.signature)
            .append("- user", &self.user)
            .appenh("- credential_id", &self.credential_id);

        for e in &self.extensions {
            if let Extension::HmacSecret(Some(output1_enc)) = e {
                let tmp = format!("- {}", Extension::HmacSecret(None));
                strbuf.appenh(&tmp, output1_enc.as_ref());
            }
        }

        write!(f, "{}", strbuf.build())
    }
}

#[derive(Debug, Clone, strum_macros::Display, AsRefStr)]
pub enum Extension {
    #[strum(serialize = "hmac-secret")]
    HmacSecret(Option<[u8; 32]>),
    #[strum(serialize = "largeBlobKey")]
    LargeBlobKey((Option<bool>, Option<Vec<u8>>)),
    #[strum(serialize = "credBlob")]
    CredBlob((Option<bool>, Option<Vec<u8>>)),
}

impl Extension {
    #[must_use]
    pub fn create_hmac_secret_from_string(message: &str) -> Self {
        let hasher = digest::digest(&digest::SHA256, message.as_bytes());
        Self::HmacSecret(Some(<[u8; 32]>::try_from(hasher.as_ref()).unwrap()))
    }
}

#[derive(Debug)]
pub struct GetAssertionArgs<'a> {
    pub rpid: String,
    pub challenge: Vec<u8>,
    pub pin: Option<&'a str>,
    pub credential_ids: Vec<Vec<u8>>,
    pub uv: Option<bool>,
    pub extensions: Option<Vec<Extension>>,
}
impl<'a> GetAssertionArgs<'a> {
    #[must_use]
    pub fn builder() -> GetAssertionArgsBuilder<'a> {
        GetAssertionArgsBuilder::default()
    }
}

#[derive(Default)]
pub struct GetAssertionArgsBuilder<'a> {
    rpid: String,
    challenge: Vec<u8>,
    pin: Option<&'a str>,
    credential_ids: Vec<Vec<u8>>,
    uv: Option<bool>,
    extensions: Option<Vec<Extension>>,
}
impl<'a> GetAssertionArgsBuilder<'a> {
    #[must_use]
    pub fn new(rpid: &str, challenge: &[u8]) -> GetAssertionArgsBuilder<'a> {
        GetAssertionArgsBuilder::<'_> {
            uv: Some(true),
            rpid: String::from(rpid),
            challenge: challenge.to_vec(),
            ..Default::default()
        }
    }

    #[must_use]
    pub const fn pin(mut self, pin: &'a str) -> GetAssertionArgsBuilder<'a> {
        self.pin = Some(pin);
        //self.uv = Some(false);
        self.uv = None;
        self
    }

    #[must_use]
    pub const fn without_pin_and_uv(mut self) -> GetAssertionArgsBuilder<'a> {
        self.pin = None;
        self.uv = None;
        self
    }

    #[must_use]
    pub fn extensions(mut self, extensions: &[Extension]) -> GetAssertionArgsBuilder<'a> {
        self.extensions = Some(extensions.to_vec());
        self
    }

    #[must_use]
    pub fn credential_id(mut self, credential_id: &[u8]) -> GetAssertionArgsBuilder<'a> {
        self.credential_ids.clear();
        self.add_credential_id(credential_id)
    }

    #[must_use]
    pub fn add_credential_id(mut self, credential_id: &[u8]) -> GetAssertionArgsBuilder<'a> {
        self.credential_ids.push(credential_id.to_vec());
        self
    }

    #[must_use]
    pub fn build(self) -> GetAssertionArgs<'a> {
        GetAssertionArgs {
            rpid: self.rpid,
            challenge: self.challenge,
            pin: self.pin,
            credential_ids: self.credential_ids,
            uv: self.uv,
            extensions: self.extensions,
        }
    }
}
