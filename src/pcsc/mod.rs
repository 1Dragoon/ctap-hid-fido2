use std::{ffi::{CStr, CString}, time::Duration};

use anyhow::{anyhow, bail, Result};
use pcsc::{
    Card, Context, Disposition, Error, Protocols, Scope, ShareMode, Transaction,
    MAX_ATR_SIZE, MAX_BUFFER_SIZE_EXTENDED,
};

pub struct Fido2Session {
    context: Context,
    reader: String,
    reader_cstr: CString,
}

impl<'a> Fido2Session {
    pub fn new(reader: String) -> Result<Self> {
        let mut pre_cstr = reader.as_bytes().to_vec();
        pre_cstr.push(0);
        let reader_cstr = CStr::from_bytes_with_nul(&pre_cstr)?;
        let context = Context::establish(Scope::User).map_err(|err| anyhow!("Failed to establish context: {err}"))?;
        let mut once = false;
        while let Err(Error::RemovedCard) =
            context.connect(reader_cstr, ShareMode::Direct, Protocols::ANY)
        {
            if !once {
                println!("Put it back!");
                once = true;
            }
            std::thread::sleep(Duration::from_millis(50))
        }

        Ok(Fido2Session {
            context,
            reader,
            reader_cstr: reader_cstr.to_owned(),
        })
    }

    pub fn card(&self) -> Result<Card> {
        self.context
        .connect(&self.reader_cstr, ShareMode::Shared, Protocols::ANY)
        .map_err(|err| anyhow!("Failed to connect to card on reader {}: {err}", self.reader))
    }

    pub fn new_transaction(&'a self, card: &'a mut Card) -> Result<Transaction<'a>> {
        let tx = card
            .transaction2()
            .map_err(|(_, err)| anyhow!("Failed to begin card transaction on reader {}: {err}", self.reader))?;
        // Get the card status.
        let status = tx
            .status2_owned()
            .map_err(|err| anyhow!("Failed to get card status on reader {}: {err}", self.reader))?;

        if status.protocol2().is_some() {
            Ok(tx)
        } else {
            bail!("Card protocol hasn't been established")
        }
    }
}

pub fn send_command(tx: &Transaction, cmd_apdu: &[u8]) -> Result<Vec<u8>> {
    let mut response_apdu = vec![0; MAX_BUFFER_SIZE_EXTENDED];
    // let mut response_apdu = vec![0; (1<<32)-1];
    tx.transmit2(cmd_apdu, &mut response_apdu)
        .map_err(|err| anyhow!("Failed to transmit command APDU: {err:?}"))?;

    // Can either end explicity, which allows error handling,
    // and setting the disposition method, or leave it to drop, which
    // swallows any error and hardcodes LeaveCard.
    // tx.end(Disposition::LeaveCard)
    //     .map_err(|(_, err)| anyhow!("Failed to end transaction: {err}"))?;

    Ok(response_apdu)
}

//                                     CLA   INS   P1    P2    Le    RID                           AX    AC           AID: RID+AX+AC
// pub const SELECT_FIDO2_APDU: &[u8] = &[0x00, 0xa4, 0x04, 0x0c, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01]; // Standard per https://fidoalliance.org/specs/fido-v2.0-rd-20170927/fido-client-to-authenticator-protocol-v2.0-rd-20170927.html#iso7816-iso14443-and-near-field-communication-nfc
pub const SELECT_FIDO2_APDU: &[u8] = &[0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01]; // Yubikeys reject the above but accept this one. Other keys I've tried work as well with this so far.
// pub const SELECT_FIDO2_APDU: &[u8] = &[0x00, 0xa4, 0x04, 0x00, 0x06, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f]; // Bypasses windows admin requirement

pub fn get_fido_pcsc_devices() -> Result<Vec<String>> {
    // Get a context.
    let ctx = Context::establish(Scope::User).expect("failed to establish context");

    // List connected readers.
    let mut readers_buf = [0; 2048];
    let readers = ctx
        .list_readers(&mut readers_buf)
        .map_err(|err| anyhow!("Failed to list PCSC readers: {err}"))?
        .collect::<Vec<_>>();
    let mut cards = Vec::new();

    if readers.is_empty() {
        return Ok(cards);
    }

    for reader in readers {
        let reader_str = reader.to_str()?.to_owned();
        let cardres = ctx.connect(reader, ShareMode::Shared, Protocols::ANY);
        let mut card = match cardres {
            Ok(ok) => ok,
            Err(err) => {
                if let Error::RemovedCard = err {
                    continue;
                } else {
                    bail!("Failed to connect to card on reader \"{reader_str}\": {err}")
                }
            }
        };
        let tx = card.transaction().map_err(|err| {
            anyhow!("Failed to begin card transaction on reader \"{reader_str}\": {err}")
        })?;

        // Get the card status.
        let (names_len, _atr_len) = tx.status2_len().map_err(|err| {
            anyhow!("Failed to get the status length on reader \"{reader_str}\": {err}")
        })?;
        let mut names_buf = vec![0; names_len];
        let mut atr_buf = [0; MAX_ATR_SIZE];
        let status = tx
            .status2(&mut names_buf, &mut atr_buf)
            .map_err(|err| anyhow!("Failed to get card status on reader \"{reader_str}\": {err}"))?;

        if status.protocol2().is_some() {
            let cmd_apdu = SELECT_FIDO2_APDU;
            let mut response_apdu = vec![0; MAX_BUFFER_SIZE_EXTENDED];
            tx.transmit(cmd_apdu, &mut response_apdu)
                .map_err(|err| anyhow!("Failed to transmit APDU to reader \"{reader_str}\": {err}"))?;

            if String::from_utf8_lossy(&response_apdu[0..16]).contains("U2F_V2") {
                cards.push(reader_str);
            }
        }

        // Can either end explicity, which allows error handling,
        // and setting the disposition method, or leave it to drop, which
        // swallows any error and hardcodes LeaveCard.
        tx.end(Disposition::LeaveCard)
            .map_err(|(_, err)| anyhow!("Failed to end transaction: {err}"))?;

        // Can either disconnect explicity, which allows error handling,
        // and setting the disposition method, or leave it to drop, which
        // swallows any error and hardcodes ResetCard.
        card.disconnect(Disposition::ResetCard)
            .map_err(|(_, err)| anyhow!("Failed to disconnect from card: {err}"))?;
    }

    // Can either release explicity, which allows error handling,
    // or leave it to drop, which swallows any error.
    // The function fails if there are any live clones.
    ctx.release()
        .map_err(|(_, err)| err)
        .expect("failed to release context");

    Ok(cards)
}
