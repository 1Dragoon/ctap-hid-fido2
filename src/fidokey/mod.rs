use crate::KeyID;
use anyhow::{anyhow, Result};
use hidapi::HidApi;
use std::ffi::CString;

// Complex Submodules
pub mod authenticator_config;
pub mod bio;
pub mod credential_management;
pub mod get_assertion;
pub mod get_info;
pub mod large_blobs;
pub mod make_credential;
pub mod pin;

// Simple Submodules
mod selection;
mod sub_command_base;
mod wink;

pub use get_assertion::{Extension as AssertionExtension, GetAssertionArgsBuilder};

pub use make_credential::{
    CredentialSupportedKeyType, Extension as CredentialExtension, MakeCredentialArgsBuilder,
};

pub trait FidoKey {
    fn new(params: &[crate::KeyID], cfg: &crate::LibCfg) -> Result<Self> where Self: std::marker::Sized;
    fn write(&self, cmd: &[u8]) -> Result<usize, String>;
    fn read(&self) -> Result<Vec<u8>, String>;
}

pub struct FidoKeyHid {
    device_internal: hidapi::HidDevice,
    pub enable_log: bool,
    pub use_pre_bio_enrollment: bool,
    pub use_pre_credential_management: bool,
    pub keep_alive_msg: String,
}

impl FidoKey for FidoKeyHid {
    fn new(params: &[crate::KeyID], cfg: &crate::LibCfg) -> Result<Self> {
        let api = HidApi::new().expect("Failed to create HidApi instance");
        for param in params {
            let path = get_path(&api, param);
            if path.is_none() {
                continue;
            }

            if let Ok(dev) = api.open_path(&path.unwrap()) {
                let result = Self {
                    device_internal: dev,
                    enable_log: cfg.enable_log,
                    use_pre_bio_enrollment: cfg.use_pre_bio_enrollment,
                    use_pre_credential_management: cfg.use_pre_credential_management,
                    keep_alive_msg: cfg.keep_alive_msg.to_string(),
                };
                return Ok(result);
            }
        }
        Err(anyhow!("Failed to open device."))
    }

    fn write(&self, cmd: &[u8]) -> Result<usize, String> {
        self.device_internal
            .write(cmd)
            .map_err(|_| "write error".into())
    }

    fn read(&self) -> Result<Vec<u8>, String> {
        let mut buf: Vec<u8> = vec![0; 64];
        self.device_internal
            .read(&mut buf[..])
            .map(|_| buf)
            .map_err(|_| "read error".into())
    }
}

/// Abstraction for getting a path from a provided `HidParam`
fn get_path(api: &hidapi::HidApi, param: &crate::KeyID) -> Option<CString> {
    match param {
        KeyID::Path(s) => {
            if let Ok(p) = CString::new(s.as_bytes()) {
                return Some(p);
            }
        }
        KeyID::VidPid { vid, pid } => {
            let devices = api.device_list();
            for x in devices {
                if x.vendor_id() == *vid && x.product_id() == *pid {
                    return Some(x.path().to_owned());
                }
            }
        }
        KeyID::Reader(s) => {
            if let Ok(p) = CString::new(s.as_bytes()) {
                return Some(p);
            }
        }
    };

    None
}
