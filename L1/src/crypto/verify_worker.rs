use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;
use std::time::Duration;
use once_cell::sync::Lazy;
use crate::crypto::batch_verify::DilithiumBatchVerifier;

/// A single verification request
pub struct VerifyReq {
    pub pubkey: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub resp: Sender<bool>,
}

pub struct VerifyWorker {
    tx: Sender<VerifyReq>,
}

impl VerifyWorker {
    pub fn new() -> Self {
        let (tx, rx): (Sender<VerifyReq>, Receiver<VerifyReq>) = channel();
        thread::spawn(move || {
            let verifier = DilithiumBatchVerifier::new(256);
            loop {
                // collect first request (blocking)
                let first = match rx.recv() {
                    Ok(r) => r,
                    Err(_) => break,
                };

                let mut batch = vec![first];

                // drain with short timeout to form a batch
                while let Ok(r) = rx.recv_timeout(Duration::from_millis(5)) {
                    batch.push(r);
                    if batch.len() >= 256 { break; }
                }

                // prepare items
                let items: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = batch.iter()
                    .map(|r| (r.pubkey.clone(), r.message.clone(), r.signature.clone()))
                    .collect();

                let results = verifier.verify_batch(&items);

                for (i, r) in batch.into_iter().enumerate() {
                    let ok = results.get(i).copied().unwrap_or(false);
                    let _ = r.resp.send(ok);
                }
            }
        });

        Self { tx }
    }

    pub fn verify_sync(&self, pubkey: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
        let (resp_tx, resp_rx) = channel();
        let req = VerifyReq { pubkey, message, signature, resp: resp_tx };
        if let Err(_) = self.tx.send(req) {
            return false;
        }
        match resp_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(v) => v,
            Err(_) => false,
        }
    }
}

pub static VERIFY_WORKER: Lazy<VerifyWorker> = Lazy::new(|| VerifyWorker::new());

pub fn verify_dilithium_batch(pubkey: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    VERIFY_WORKER.verify_sync(pubkey, message, signature)
}
