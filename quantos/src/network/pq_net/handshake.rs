//! TCP PQ handshake: Kyber768 encapsulation + mutual ML-DSA (Dilithium3) signatures.

use std::io;

use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber768;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::crypto::sign_dilithium;
use crate::crypto::{verify_dilithium, DilithiumKeypair, KemKeypair};
use crate::crypto::{derive_channel_key, kem_handshake_transcript};
use crate::network::peer_id::PeerId;
use crate::network::pq_identity::peer_id_from_dilithium_public_key;
use crate::network::pq_net::session_crypto::{SessionDecrypt, SessionEncrypt};

const MAGIC: &[u8; 4] = b"QTP1";
const MSG_INIT: u8 = 1;
const MSG_RESP: u8 = 2;
const MSG_FIN: u8 = 3;

const PK_D: usize = dilithium3::public_key_bytes();
const SIG_D: usize = dilithium3::signature_bytes();
const PK_K: usize = kyber768::public_key_bytes();
const CT_K: usize = kyber768::ciphertext_bytes();

#[derive(Debug)]
pub struct HandshakeError(pub String);

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HandshakeError {}

fn binding_material(
    nonce: &[u8; 32],
    dil_i: &[u8],
    dil_r: &[u8],
    kem_i: &[u8],
    kem_r: &[u8],
    ct: &[u8],
    sig_r: &[u8],
    sig_i: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(
        32 + dil_i.len() + dil_r.len() + kem_i.len() + kem_r.len() + ct.len() + sig_r.len() + sig_i.len(),
    );
    v.extend_from_slice(nonce);
    v.extend_from_slice(dil_i);
    v.extend_from_slice(dil_r);
    v.extend_from_slice(kem_i);
    v.extend_from_slice(kem_r);
    v.extend_from_slice(ct);
    v.extend_from_slice(sig_r);
    v.extend_from_slice(sig_i);
    v
}

fn split_keys(ss: &[u8], binding: &[u8]) -> Result<([u8; 32], [u8; 32]), HandshakeError> {
    let mut info_ir = binding.to_vec();
    info_ir.extend_from_slice(b"|i>r");
    let mut info_ri = binding.to_vec();
    info_ri.extend_from_slice(b"|r>i");
    let k_ir = derive_channel_key(ss, &info_ir).map_err(|e| HandshakeError(e.to_string()))?;
    let k_ri = derive_channel_key(ss, &info_ri).map_err(|e| HandshakeError(e.to_string()))?;
    Ok((k_ir, k_ri))
}

pub struct SecureTransport {
    pub enc: SessionEncrypt,
    pub dec: SessionDecrypt,
    pub remote_peer_id: PeerId,
}

/// Initiator: we opened the TCP connection.
pub async fn client_handshake(
    stream: &mut TcpStream,
    dilithium: &DilithiumKeypair,
    kem: &KemKeypair,
    expected_remote: PeerId,
) -> Result<SecureTransport, HandshakeError> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut out = Vec::with_capacity(MAGIC.len() + 1 + PK_D + PK_K + 32);
    out.extend_from_slice(MAGIC);
    out.push(MSG_INIT);
    out.extend_from_slice(&dilithium.public_key);
    out.extend_from_slice(&kem.public_key);
    out.extend_from_slice(&nonce);
    stream.write_all(&out).await.map_err(|e| HandshakeError(e.to_string()))?;

    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).await.map_err(|e| HandshakeError(e.to_string()))?;
    if &hdr[..4] != MAGIC {
        return Err(HandshakeError("bad magic (resp)".into()));
    }
    if hdr[4] != MSG_RESP {
        return Err(HandshakeError("unexpected responder msg".into()));
    }

    let mut dil_r = vec![0u8; PK_D];
    let mut kem_r = vec![0u8; PK_K];
    let mut ct = vec![0u8; CT_K];
    let mut sig_r = vec![0u8; SIG_D];
    stream.read_exact(&mut dil_r).await.map_err(|e| HandshakeError(e.to_string()))?;
    stream.read_exact(&mut kem_r).await.map_err(|e| HandshakeError(e.to_string()))?;
    stream.read_exact(&mut ct).await.map_err(|e| HandshakeError(e.to_string()))?;
    stream.read_exact(&mut sig_r).await.map_err(|e| HandshakeError(e.to_string()))?;

    let remote_pid = peer_id_from_dilithium_public_key(&dil_r);
    if remote_pid != expected_remote {
        return Err(HandshakeError(format!(
            "peer id mismatch: expected {} got {}",
            expected_remote, remote_pid
        )));
    }

    let tr_r = kem_handshake_transcript(1, &dilithium.public_key, &dil_r, &kem.public_key, &kem_r, &ct);
    let ok = verify_dilithium(&dil_r, &tr_r, &sig_r).map_err(|e| HandshakeError(e.to_string()))?;
    if !ok {
        return Err(HandshakeError("responder signature invalid".into()));
    }

    let ss = kem.decapsulate(&ct).map_err(|e| HandshakeError(e.to_string()))?;

    let tr_i = kem_handshake_transcript(0, &dilithium.public_key, &dil_r, &kem.public_key, &kem_r, &ct);
    let sig_i = sign_dilithium(&dilithium.secret_key, &tr_i).map_err(|e| HandshakeError(e.to_string()))?;
    if sig_i.len() != SIG_D {
        return Err(HandshakeError("bad sig length".into()));
    }

    let mut fin = Vec::with_capacity(MAGIC.len() + 1 + SIG_D);
    fin.extend_from_slice(MAGIC);
    fin.push(MSG_FIN);
    fin.extend_from_slice(&sig_i);
    stream.write_all(&fin).await.map_err(|e| HandshakeError(e.to_string()))?;

    let bind = binding_material(&nonce, &dilithium.public_key, &dil_r, &kem.public_key, &kem_r, &ct, &sig_r, &sig_i);
    let (k_ir, k_ri) = split_keys(&ss, &bind)?;

    Ok(SecureTransport {
        enc: SessionEncrypt::new(&k_ir, 1).map_err(|e| HandshakeError(e.to_string()))?,
        dec: SessionDecrypt::new(&k_ri).map_err(|e| HandshakeError(e.to_string()))?,
        remote_peer_id: remote_pid,
    })
}

/// Responder: inbound TCP accepted.
pub async fn server_handshake(
    stream: &mut TcpStream,
    dilithium: &DilithiumKeypair,
    kem: &KemKeypair,
) -> Result<SecureTransport, HandshakeError> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).await.map_err(|e| HandshakeError(e.to_string()))?;
    if &hdr[..4] != MAGIC {
        return Err(HandshakeError("bad magic (init)".into()));
    }
    if hdr[4] != MSG_INIT {
        return Err(HandshakeError("unexpected initiator msg".into()));
    }

    let mut dil_i = vec![0u8; PK_D];
    let mut kem_i = vec![0u8; PK_K];
    let mut nonce = [0u8; 32];
    stream.read_exact(&mut dil_i).await.map_err(|e| HandshakeError(e.to_string()))?;
    stream.read_exact(&mut kem_i).await.map_err(|e| HandshakeError(e.to_string()))?;
    stream.read_exact(&mut nonce).await.map_err(|e| HandshakeError(e.to_string()))?;

    let (ss, ct_vec) = KemKeypair::encapsulate(&kem_i).map_err(|e| HandshakeError(e.to_string()))?;
    if ct_vec.len() != CT_K {
        return Err(HandshakeError("bad kyber ct length".into()));
    }
    let ct = ct_vec;

    let tr_r = kem_handshake_transcript(1, &dil_i, &dilithium.public_key, &kem_i, &kem.public_key, &ct);
    let sig_r = sign_dilithium(&dilithium.secret_key, &tr_r).map_err(|e| HandshakeError(e.to_string()))?;

    let mut out = Vec::with_capacity(MAGIC.len() + 1 + PK_D + PK_K + CT_K + SIG_D);
    out.extend_from_slice(MAGIC);
    out.push(MSG_RESP);
    out.extend_from_slice(&dilithium.public_key);
    out.extend_from_slice(&kem.public_key);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&sig_r);
    stream.write_all(&out).await.map_err(|e| HandshakeError(e.to_string()))?;

    let mut rh = [0u8; 5];
    stream.read_exact(&mut rh).await.map_err(|e| HandshakeError(e.to_string()))?;
    if &rh[..4] != MAGIC {
        return Err(HandshakeError("bad magic (fin)".into()));
    }
    if rh[4] != MSG_FIN {
        return Err(HandshakeError("unexpected fin msg".into()));
    }

    let mut sig_i = vec![0u8; SIG_D];
    stream.read_exact(&mut sig_i).await.map_err(|e| HandshakeError(e.to_string()))?;

    let tr_i = kem_handshake_transcript(0, &dil_i, &dilithium.public_key, &kem_i, &kem.public_key, &ct);
    let ok = verify_dilithium(&dil_i, &tr_i, &sig_i).map_err(|e| HandshakeError(e.to_string()))?;
    if !ok {
        return Err(HandshakeError("initiator signature invalid".into()));
    }

    let bind = binding_material(&nonce, &dil_i, &dilithium.public_key, &kem_i, &kem.public_key, &ct, &sig_r, &sig_i);
    let (k_ir, k_ri) = split_keys(&ss, &bind)?;

    let remote_peer_id = peer_id_from_dilithium_public_key(&dil_i);

    Ok(SecureTransport {
        // Responder sends on k_ri->k_ir channel (responder-to-initiator), reads k_ir->k_ri
        enc: SessionEncrypt::new(&k_ri, 2).map_err(|e| HandshakeError(e.to_string()))?,
        dec: SessionDecrypt::new(&k_ir).map_err(|e| HandshakeError(e.to_string()))?,
        remote_peer_id,
    })
}

pub fn io_err(e: HandshakeError) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, e.0)
}
