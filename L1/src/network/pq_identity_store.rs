//! Persisted PQ node identity (Dilithium3 + Kyber768) for stable [`PeerId`] across restarts.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use pqcrypto_dilithium::dilithium3;

use crate::crypto::{DilithiumKeypair, KemKeypair};
use crate::network::{NetworkError, NetworkResult};

const MAGIC: &[u8; 4] = b"QPK1";
const FORMAT_VERSION: u32 = 1;

#[must_use]
pub fn resolve_identity_path(db_path: &str) -> PathBuf {
    if let Ok(p) = std::env::var("QUANTOS_P2P_IDENTITY_PATH") {
        PathBuf::from(p.trim())
    } else {
        Path::new(db_path).join("p2p").join("pq_identity.qpk")
    }
}

fn read_u32_le(bs: &[u8], i: &mut usize) -> NetworkResult<u32> {
    let end = (*i).checked_add(4).ok_or_else(|| NetworkError::InvalidMessage("identity corrupt".into()))?;
    let sl = bs.get(*i..end).ok_or_else(|| NetworkError::InvalidMessage("identity truncated".into()))?;
    *i = end;
    Ok(u32::from_le_bytes(sl.try_into().map_err(|_| NetworkError::InvalidMessage("identity bad u32".into()))?))
}

/// Loads PQ identity from disk or generates + atomically writes a new file.
pub fn load_or_create_identity(db_path: &str) -> NetworkResult<(DilithiumKeypair, KemKeypair)> {
    let path = resolve_identity_path(db_path);
    if path.is_file() {
        return load_identity_file(&path);
    }

    let dil = DilithiumKeypair::generate()
        .map_err(|e| NetworkError::ConnectionFailed(format!("Dilithium generate: {}", e)))?;
    let kem = KemKeypair::generate()
        .map_err(|e| NetworkError::ConnectionFailed(format!("Kyber generate: {}", e)))?;

    write_identity_atomic(&path, &dil, &kem)?;

    tracing::info!("Created new PQ P2P identity at {}", path.display());
    Ok((dil, kem))
}

fn load_identity_file(path: &Path) -> NetworkResult<(DilithiumKeypair, KemKeypair)> {
    let mut f = File::open(path).map_err(|e| NetworkError::IoError(e.to_string()))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| NetworkError::IoError(e.to_string()))?;

    if buf.len() < MAGIC.len() + 4 {
        return Err(NetworkError::InvalidMessage("identity file too small".into()));
    }
    if &buf[..MAGIC.len()] != MAGIC {
        return Err(NetworkError::InvalidMessage("identity bad magic".into()));
    }

    let mut i = MAGIC.len();
    let ver = read_u32_le(&buf, &mut i)?;
    if ver != FORMAT_VERSION {
        return Err(NetworkError::InvalidMessage(format!(
            "unsupported identity format version {}",
            ver
        )));
    }

    let dil_sk_len = read_u32_le(&buf, &mut i)? as usize;
    if dil_sk_len != dilithium3::secret_key_bytes() {
        return Err(NetworkError::InvalidMessage("bad Dilithium secret length".into()));
    }
    let dil_sk = buf
        .get(i..i + dil_sk_len)
        .ok_or_else(|| NetworkError::InvalidMessage("identity truncated (dilithium)".into()))?
        .to_vec();
    i += dil_sk_len;

    let kem_pk_len = read_u32_le(&buf, &mut i)? as usize;
    let kem_pk = buf
        .get(i..i + kem_pk_len)
        .ok_or_else(|| NetworkError::InvalidMessage("identity truncated (kem pk)".into()))?
        .to_vec();
    i += kem_pk_len;

    let kem_sk_len = read_u32_le(&buf, &mut i)? as usize;
    let kem_sk = buf
        .get(i..i + kem_sk_len)
        .ok_or_else(|| NetworkError::InvalidMessage("identity truncated (kem sk)".into()))?
        .to_vec();
    i += kem_sk_len;

    if i != buf.len() {
        return Err(NetworkError::InvalidMessage("identity trailing garbage".into()));
    }

    let dil = DilithiumKeypair::from_secret_key(&dil_sk)
        .map_err(|e| NetworkError::InvalidMessage(format!("bad Dilithium material: {}", e)))?;
    let kem = KemKeypair::from_storage(kem_pk, kem_sk)
        .map_err(|e| NetworkError::InvalidMessage(format!("bad Kyber material: {}", e)))?;

    tracing::info!("Loaded PQ P2P identity from {}", path.display());
    Ok((dil, kem))
}

fn write_identity_atomic(path: &Path, dil: &DilithiumKeypair, kem: &KemKeypair) -> NetworkResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| NetworkError::IoError(e.to_string()))?;
    }

    let mut payload = Vec::new();
    payload.extend_from_slice(MAGIC);
    payload.extend_from_slice(&FORMAT_VERSION.to_le_bytes());

    let dil_sk = dil.secret_key.as_slice();
    payload.extend_from_slice(&(dil_sk.len() as u32).to_le_bytes());
    payload.extend_from_slice(dil_sk);

    let kem_pk = kem.public_key_slice();
    payload.extend_from_slice(&(kem_pk.len() as u32).to_le_bytes());
    payload.extend_from_slice(kem_pk);

    let kem_sk = kem.secret_key_slice();
    payload.extend_from_slice(&(kem_sk.len() as u32).to_le_bytes());
    payload.extend_from_slice(kem_sk);

    let tmp = path.with_extension("qpk.tmp");
    {
        let mut f = File::create(&tmp).map_err(|e| NetworkError::IoError(e.to_string()))?;
        f.write_all(&payload).map_err(|e| NetworkError::IoError(e.to_string()))?;
        f.sync_all().map_err(|e| NetworkError::IoError(e.to_string()))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp)
            .map_err(|e| NetworkError::IoError(e.to_string()))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&tmp, perms).map_err(|e| NetworkError::IoError(e.to_string()))?;
    }

    fs::rename(&tmp, path).map_err(|e| NetworkError::IoError(e.to_string()))?;
    Ok(())
}
