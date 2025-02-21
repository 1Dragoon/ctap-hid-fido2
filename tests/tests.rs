//
// cargo test -- --test-threads=1
//

use ctap_hid_fido2::*;
use fidokey::get_info::{InfoOption, InfoParam};
use fidokey::MakeCredentialArgsBuilder;

#[test]
fn test_get_hid_devices() {
    let _ = get_hid_devices();
}

#[test]
fn test_wink() {
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    device.wink().unwrap();
}

#[test]
fn test_get_info() {
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    device.get_info().unwrap();
}

#[test]
fn test_get_info_u2f() {
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    match device.enable_info_param(&InfoParam::VersionsU2Fv2) {
        Ok(result) => {
            if !result {
                // Skip
                return;
            }
        }
        Err(_) => panic!(),
    };

    device.get_info_u2f().unwrap();
}

#[test]
fn test_client_pin_get_retries() {
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    let retry = device.get_pin_retries();
    println!("- retries = {:?}", retry);
}

#[test]
fn test_make_credential_with_pin_non_rk() {
    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    let att = device.make_credential(rpid, &challenge, Some(pin)).unwrap();
    println!("Attestation");
    println!("{}", att);

    let ass = device
        .get_assertion(rpid, &challenge, &[att.credential_descriptor.id], Some(pin))
        .unwrap();
    println!("Assertion");
    println!("{}", ass);
}

#[test]
fn test_make_credential_with_pin_non_rk_exclude_authenticator() {
    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .build();

    let att = device
        .make_credential_with_args(&make_credential_args)
        .unwrap();

    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);
    assert!(verify_result.is_success);

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .exclude_authenticator(&verify_result.credential_id)
        .build();

    let result = device.make_credential_with_args(&make_credential_args);
    assert!(result.is_err());
}

#[test]
fn test_credential_management_get_creds_metadata() {
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    match device.enable_info_param(&InfoParam::VersionsFido21Pre) {
        Ok(result) => {
            if !result {
                // Skip
                return;
            }
        }
        Err(_) => panic!(),
    };

    let pin = "1234";
    assert!(device
        .credential_management_get_creds_metadata(Some(pin))
        .is_ok());
}

#[test]
fn test_credential_management_enumerate_rps() {
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    match device.enable_info_param(&InfoParam::VersionsFido21Pre) {
        Ok(result) => {
            if !result {
                // Skip
                return;
            }
        }
        Err(_) => panic!(),
    };

    let pin = "1234";
    assert!(device
        .credential_management_enumerate_rps(Some(pin))
        .is_ok());
}

#[test]
fn test_bio_enrollment_get_fingerprint_sensor_info() {
    let mut skip = true;

    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();

    match device.enable_info_option(&InfoOption::UserVerificationMgmtPreview) {
        Ok(result) => {
            //println!("result = {:?}", result);
            if let Some(v) = result {
                //println!("some value = {}", v);
                if v {
                    skip = false
                };
            }
        }
        Err(_) => panic!(),
    };

    // skip
    if skip {
        return;
    };

    assert!(device.bio_enrollment_get_fingerprint_sensor_info().is_ok());
}

#[test]
fn test_bio_enrollment_enumerate_enrollments() {
    let mut skip = true;

    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();

    match device.enable_info_option(&InfoOption::UserVerificationMgmtPreview) {
        Ok(result) => {
            if let Some(v) = result {
                if v {
                    skip = false
                };
            }
        }
        Err(_) => panic!(),
    };

    if skip {
        return;
    };

    let pin = "1234";
    assert!(device.bio_enrollment_enumerate_enrollments(pin).is_ok());
}
