use ctap_hid_fido2;
use ctap_hid_fido2::util;

fn main() {
    println!("----- test-with-pin-non-rk start -----");

    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    println!("make_credential()");
    let att = match ctap_hid_fido2::make_credential(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        pin,
    ) {
        Ok(result) => result,
        Err(err) => {
            println!("- Register Error {:?}", err);
            return;
        }
    };

    println!("- Register Success!!");
    att.print("Attestation");

    println!("get_assertion_with_pin()");
    let att = match ctap_hid_fido2::get_assertion(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        &att.credential_id,
        pin,
    ) {
        Ok(result) => result,
        Err(err) => {
            println!("- Authenticate Error {:?}", err);
            return;
        }
    };
    println!("- Authenticate Success!!");
    println!("- sign_count = {:?}", att.sign_count);
    println!(
        "- signature({:02}) = {:?}",
        att.signature.len(),
        util::to_hex_str(&att.signature)
    );

    println!("----- test-with-pin-non-rk end -----");
}
