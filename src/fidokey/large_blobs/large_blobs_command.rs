use crate::{ctapdef, encrypt::enc_hmac_sha_256, pintoken::PinToken};
use anyhow::Result;
use ring::digest;
use serde_cbor::{to_vec, Value};
use std::collections::BTreeMap;

pub fn create_payload(
    pin_token: Option<PinToken>,
    offset: u32,
    get: Option<u32>,
    set: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    // create cbor
    let mut map = BTreeMap::new();

    // 0x01: get
    if let Some(read_bytes) = get {
        map.insert(Value::Integer(0x01), Value::Integer(i128::from(read_bytes)));
    }

    // 0x03: offset
    map.insert(Value::Integer(0x03), Value::Integer(i128::from(offset)));

    if let Some(write_data) = set {
        let large_blob_array = create_large_blob_array(&write_data);

        // 0x02: set
        map.insert(Value::Integer(0x02), Value::Bytes(large_blob_array.clone()));

        // 0x04: length
        map.insert(
            Value::Integer(0x04),
            Value::Integer(large_blob_array.len() as i128),
        );

        // 0x05: pinUvAuthParam
        // 0x06: pinUvAuthProtocol
        if let Some(pin_token) = pin_token {
            // pinUvAuthParam
            //   authenticate(
            //     pinUvAuthToken,
            //     32×0xff
            //       || h’0c00'
            //       || uint32LittleEndian(offset)
            //       || SHA-256(contents of set byte string, i.e. not including an outer CBOR tag with major type two)
            //   )
            // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW

            let pin_uv_auth_param = {
                // println!("- {:?}", util::to_hex_str(&large_blob_array));
                // println!("- {:?}", offset);
                // println!("- {:?}", large_blob_array.len());

                let mut message = vec![0xff; 32];
                message.append(&mut vec![0x0c, 0x00]);
                message.append(&mut offset.to_le_bytes().to_vec());

                let hash = digest::digest(&digest::SHA256, &large_blob_array);
                message.append(&mut hash.as_ref().to_vec());

                let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
                sig[0..16].to_vec()
            };
            map.insert(Value::Integer(0x05), Value::Bytes(pin_uv_auth_param));
            map.insert(Value::Integer(0x06), Value::Integer(1));
        }
    }

    // CBOR
    let cbor = Value::Map(map);
    let mut payload = [ctapdef::AUTHENTICATOR_LARGEBLOBS].to_vec();
    payload.append(&mut to_vec(&cbor)?);
    Ok(payload)
}

fn create_large_blob_array(write_data: &[u8]) -> Vec<u8> {
    let mut large_blob_array = write_data.to_vec();

    let hash = digest::digest(&digest::SHA256, &large_blob_array);
    let message = &hash.as_ref()[0..16];

    //println!("- data: {:?}", util::to_hex_str(&data));
    //println!("- message: {:?}", util::to_hex_str(message));

    large_blob_array.append(&mut message.to_vec());

    //println!("- large_blob_array: {:?}", util::to_hex_str(&large_blob_array));

    large_blob_array
}
