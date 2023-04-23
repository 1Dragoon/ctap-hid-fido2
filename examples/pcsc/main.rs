use std::collections::BTreeMap;

use ctap_hid_fido2::pcsc::{get_fido_pcsc_devices, Fido2Session, send_command, SELECT_FIDO2_APDU};
use anyhow::Result;
use serde_cbor::Value;

fn main() -> Result<()> {
    let fidos = get_fido_pcsc_devices()?;
    let reader = fidos[0].clone();
    println!("{fidos:?}");
    let sess = Fido2Session::new(reader)?;
    let mut card = sess.card()?;
    let tx = sess.new_transaction(&mut card)?;

    let resp = send_command(&tx, SELECT_FIDO2_APDU)?;
    println!("resp: {:02x?}", &resp[0..8]);
    let resp = send_command(&tx, &[0x80, 0x10, 0x00, 0x00, 0x01, 0x04])?;
    // let resp = send_command(&tx, &[0x00, 0x04, 0x00, 0x00])?;
    println!("resp: {:02x?}", &resp[0..32]);
    println!("{}", String::from_utf8_lossy(resp.as_slice()));
    let val = serde_cbor::from_slice::<Value>(&resp.as_slice()[1..115]).unwrap();
    println!("{val:?}");
    // let resp = send_command(&tx, &[0x00, 0x03, 0x00, 0x00, 0x0D, 0x00, 0x40, 0x00, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])?;
    // println!("resp: {:02x?}", &resp[0..8]);
    Ok(())
}
