use crate::error::{AppError, AppResult};
use crate::security::MasterKeyStore;
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

// Keep one temporary part below 1 GB so very large uploads can proceed even
// when the source file leaves relatively little free local disk space.
pub const TELEGRAM_SAFE_CHUNK_BYTES: u64 = 1_000_000_000;
const BUFFER_BYTES: usize = 8 * 1024 * 1024;
const ENCRYPTED_MAGIC: &[u8; 8] = b"TVENC001";
pub const PREVIEW_BLOCK_BYTES: u64 = BUFFER_BYTES as u64;
pub const ENCRYPTED_MAGIC_BYTES: u64 = ENCRYPTED_MAGIC.len() as u64;
pub const ENCRYPTED_FRAME_OVERHEAD_BYTES: u64 = 4 + 24 + 16;

#[derive(Debug, Clone)]
pub struct PreparedChunk {
    pub path: PathBuf,
    pub index: u32,
    pub size: u64,
    pub sha256: String,
    pub temporary: bool,
}

#[cfg(test)]
#[derive(Debug)]
pub struct PreparedUpload {
    pub chunks: Vec<PreparedChunk>,
    pub original_sha256: String,
    pub wrapped_key: Option<String>,
    pub key_nonce: Option<String>,
}

#[derive(Debug)]
pub struct PreparedUploadMetadata {
    pub original_sha256: String,
    pub wrapped_key: Option<String>,
    pub key_nonce: Option<String>,
}

pub fn estimate_chunks(size: u64) -> u32 {
    size.div_ceil(TELEGRAM_SAFE_CHUNK_BYTES).max(1) as u32
}

pub fn encrypted_chunk_plain_size(size: u64) -> AppResult<u64> {
    if size < ENCRYPTED_MAGIC_BYTES {
        return Err(AppError::Crypto(
            "Encrypted chunk is smaller than its header".into(),
        ));
    }
    let payload = size - ENCRYPTED_MAGIC_BYTES;
    if payload == 0 {
        return Ok(0);
    }
    let frame_storage = PREVIEW_BLOCK_BYTES + ENCRYPTED_FRAME_OVERHEAD_BYTES;
    let frames = payload.div_ceil(frame_storage);
    let overhead = frames
        .checked_mul(ENCRYPTED_FRAME_OVERHEAD_BYTES)
        .ok_or_else(|| AppError::Crypto("Encrypted chunk size overflow".into()))?;
    let plain = payload
        .checked_sub(overhead)
        .ok_or_else(|| AppError::Crypto("Encrypted chunk framing is invalid".into()))?;
    if plain == 0 || plain > frames * PREVIEW_BLOCK_BYTES {
        return Err(AppError::Crypto(
            "Encrypted chunk framing is invalid".into(),
        ));
    }
    Ok(plain)
}

pub fn decrypt_encrypted_frame(frame: &[u8], file_key: &[u8; 32]) -> AppResult<Vec<u8>> {
    if frame.len() < ENCRYPTED_FRAME_OVERHEAD_BYTES as usize {
        return Err(AppError::Crypto(
            "Encrypted preview frame is incomplete".into(),
        ));
    }
    let plain_len = u32::from_le_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| AppError::Crypto("Encrypted frame length is invalid".into()))?,
    ) as usize;
    if plain_len == 0 || plain_len > BUFFER_BYTES || frame.len() != plain_len + 44 {
        return Err(AppError::Crypto(
            "Encrypted preview frame length is invalid".into(),
        ));
    }
    let nonce = &frame[4..28];
    let cipher = XChaCha20Poly1305::new(file_key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), &frame[28..])
        .map_err(|_| {
            AppError::Crypto("Preview authentication failed; the file may be damaged".into())
        })
}

pub fn append_chunk_to_file_with_progress<F>(
    input: &Path,
    output: &Path,
    encrypted: bool,
    file_key: Option<&[u8; 32]>,
    truncate: bool,
    mut progress: F,
) -> AppResult<u64>
where
    F: FnMut(u64) -> bool,
{
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(truncate)
        .append(!truncate)
        .open(output)?;
    let mut writer = BufWriter::with_capacity(BUFFER_BYTES, file);
    let mut processed = 0u64;
    if encrypted {
        let key = file_key.ok_or_else(|| AppError::Crypto("Missing file decryption key".into()))?;
        let cipher = XChaCha20Poly1305::new(key.into());
        let mut reader = BufReader::with_capacity(BUFFER_BYTES, File::open(input)?);
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;
        if &magic != ENCRYPTED_MAGIC {
            return Err(AppError::Crypto("Encrypted chunk header is invalid".into()));
        }
        loop {
            let mut length = [0u8; 4];
            match reader.read_exact(&mut length) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(error.into()),
            }
            let plain_len = u32::from_le_bytes(length) as usize;
            if plain_len == 0 || plain_len > BUFFER_BYTES {
                return Err(AppError::Crypto(
                    "Encrypted chunk frame length is invalid".into(),
                ));
            }
            let mut nonce = [0u8; 24];
            reader.read_exact(&mut nonce)?;
            let mut ciphertext = vec![0u8; plain_len + 16];
            reader.read_exact(&mut ciphertext)?;
            let plaintext = cipher
                .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
                .map_err(|_| {
                    AppError::Crypto("Chunk authentication failed; the file may be damaged".into())
                })?;
            writer.write_all(&plaintext)?;
            processed += plaintext.len() as u64;
            if !progress(processed) {
                return Err(AppError::Message("Transfer cancelled".into()));
            }
        }
    } else {
        let mut reader = BufReader::with_capacity(BUFFER_BYTES, File::open(input)?);
        let mut buffer = vec![0u8; BUFFER_BYTES];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            writer.write_all(&buffer[..read])?;
            processed += read as u64;
            if !progress(processed) {
                return Err(AppError::Message("Transfer cancelled".into()));
            }
        }
    }
    writer.flush()?;
    Ok(processed)
}

pub fn prepare_upload_streaming_with_progress<F, C>(
    source: &Path,
    work_dir: &Path,
    encrypt: bool,
    master: &MasterKeyStore,
    mut progress: F,
    mut on_chunk: C,
) -> AppResult<PreparedUploadMetadata>
where
    F: FnMut(u64, u64) -> bool,
    C: FnMut(PreparedChunk) -> bool,
{
    fs::create_dir_all(work_dir)?;
    if encrypt {
        prepare_encrypted_streaming(
            source,
            work_dir,
            master,
            TELEGRAM_SAFE_CHUNK_BYTES,
            &mut progress,
            &mut on_chunk,
        )
    } else {
        prepare_plain_streaming(
            source,
            work_dir,
            TELEGRAM_SAFE_CHUNK_BYTES,
            &mut progress,
            &mut on_chunk,
        )
    }
}

#[cfg(test)]
fn prepare_with_limit(
    source: &Path,
    work_dir: &Path,
    encrypt: bool,
    master: &MasterKeyStore,
    max_chunk: u64,
) -> AppResult<PreparedUpload> {
    prepare_with_limit_and_progress(source, work_dir, encrypt, master, max_chunk, &mut |_, _| {
        true
    })
}

#[cfg(test)]
fn prepare_with_limit_and_progress(
    source: &Path,
    work_dir: &Path,
    encrypt: bool,
    master: &MasterKeyStore,
    max_chunk: u64,
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> AppResult<PreparedUpload> {
    fs::create_dir_all(work_dir)?;
    if encrypt {
        prepare_encrypted(source, work_dir, master, max_chunk, progress)
    } else {
        prepare_plain(source, work_dir, max_chunk, progress)
    }
}

#[cfg(test)]
fn prepare_plain(
    source: &Path,
    work_dir: &Path,
    max_chunk: u64,
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> AppResult<PreparedUpload> {
    let size = source.metadata()?.len();
    if size <= max_chunk {
        let hash = sha256_file_with_progress(source, progress)?;
        return Ok(PreparedUpload {
            chunks: vec![PreparedChunk {
                path: source.to_path_buf(),
                index: 0,
                size,
                sha256: hash.clone(),
                temporary: false,
            }],
            original_sha256: hash,
            wrapped_key: None,
            key_nonce: None,
        });
    }
    let mut reader = BufReader::with_capacity(BUFFER_BYTES, File::open(source)?);
    let mut original = Sha256::new();
    let mut chunks = Vec::new();
    let mut buffer = vec![0u8; BUFFER_BYTES];
    let mut current: Option<(BufWriter<File>, PathBuf, Sha256, u64)> = None;
    let mut index = 0u32;
    let mut processed = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        original.update(&buffer[..read]);
        processed += read as u64;
        if !progress(processed, size) {
            return Err(AppError::Message("Transfer cancelled".into()));
        }
        let mut offset = 0;
        while offset < read {
            if current.is_none() {
                let path = work_dir.join(format!("part-{index:06}.tvchunk"));
                current = Some((
                    BufWriter::with_capacity(BUFFER_BYTES, File::create(&path)?),
                    path,
                    Sha256::new(),
                    0,
                ));
            }
            let (writer, _, hasher, written) = current.as_mut().unwrap();
            let available = (max_chunk - *written) as usize;
            let take = available.min(read - offset);
            writer.write_all(&buffer[offset..offset + take])?;
            hasher.update(&buffer[offset..offset + take]);
            *written += take as u64;
            offset += take;
            if *written == max_chunk {
                finish_plain_chunk(&mut chunks, current.take().unwrap(), index)?;
                index += 1;
            }
        }
    }
    if let Some(chunk) = current.take() {
        finish_plain_chunk(&mut chunks, chunk, index)?;
    }
    Ok(PreparedUpload {
        chunks,
        original_sha256: hex::encode(original.finalize()),
        wrapped_key: None,
        key_nonce: None,
    })
}

#[cfg(test)]
fn finish_plain_chunk(
    chunks: &mut Vec<PreparedChunk>,
    chunk: (BufWriter<File>, PathBuf, Sha256, u64),
    index: u32,
) -> AppResult<()> {
    let (mut writer, path, hasher, size) = chunk;
    writer.flush()?;
    chunks.push(PreparedChunk {
        path,
        index,
        size,
        sha256: hex::encode(hasher.finalize()),
        temporary: true,
    });
    Ok(())
}

#[cfg(test)]
fn prepare_encrypted(
    source: &Path,
    work_dir: &Path,
    master: &MasterKeyStore,
    max_chunk: u64,
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> AppResult<PreparedUpload> {
    if max_chunk < (ENCRYPTED_MAGIC.len() + 4 + 24 + 16 + 1) as u64 {
        return Err(AppError::Crypto("Chunk size is too small".into()));
    }
    let mut file_key = [0u8; 32];
    rand::rng().fill_bytes(&mut file_key);
    let cipher = XChaCha20Poly1305::new((&file_key).into());
    let (wrapped_key, key_nonce) = master.wrap_file_key(&file_key)?;
    let mut reader = BufReader::with_capacity(BUFFER_BYTES, File::open(source)?);
    let mut original = Sha256::new();
    let mut chunks = Vec::new();
    let mut input = vec![0u8; BUFFER_BYTES.min((max_chunk / 2).max(1) as usize)];
    let mut current: Option<(BufWriter<File>, PathBuf, Sha256, u64)> = None;
    let mut index = 0u32;
    let total = source.metadata()?.len();
    let mut processed = 0u64;
    loop {
        let read = reader.read(&mut input)?;
        if read == 0 {
            break;
        }
        original.update(&input[..read]);
        processed += read as u64;
        if !progress(processed, total) {
            return Err(AppError::Message("Transfer cancelled".into()));
        }
        let mut nonce = [0u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), &input[..read])
            .map_err(|_| AppError::Crypto("Unable to encrypt a file block".into()))?;
        let frame_size = 4 + nonce.len() + ciphertext.len();
        if current
            .as_ref()
            .map(|x| x.3 + frame_size as u64 > max_chunk)
            .unwrap_or(true)
        {
            if let Some(chunk) = current.take() {
                finish_encrypted_chunk(&mut chunks, chunk, index)?;
                index += 1;
            }
            let path = work_dir.join(format!("part-{index:06}.tve"));
            let mut writer = BufWriter::with_capacity(BUFFER_BYTES, File::create(&path)?);
            writer.write_all(ENCRYPTED_MAGIC)?;
            let mut hasher = Sha256::new();
            hasher.update(ENCRYPTED_MAGIC);
            current = Some((writer, path, hasher, ENCRYPTED_MAGIC.len() as u64));
        }
        let (writer, _, hasher, written) = current.as_mut().unwrap();
        let length = (read as u32).to_le_bytes();
        writer.write_all(&length)?;
        writer.write_all(&nonce)?;
        writer.write_all(&ciphertext)?;
        hasher.update(length);
        hasher.update(nonce);
        hasher.update(&ciphertext);
        *written += frame_size as u64;
    }
    if let Some(chunk) = current.take() {
        finish_encrypted_chunk(&mut chunks, chunk, index)?;
    }
    if chunks.is_empty() {
        let path = work_dir.join("part-000000.tve");
        fs::write(&path, ENCRYPTED_MAGIC)?;
        chunks.push(PreparedChunk {
            path,
            index: 0,
            size: ENCRYPTED_MAGIC.len() as u64,
            sha256: hex::encode(Sha256::digest(ENCRYPTED_MAGIC)),
            temporary: true,
        });
    }
    file_key.fill(0);
    Ok(PreparedUpload {
        chunks,
        original_sha256: hex::encode(original.finalize()),
        wrapped_key: Some(wrapped_key),
        key_nonce: Some(key_nonce),
    })
}

#[cfg(test)]
fn finish_encrypted_chunk(
    chunks: &mut Vec<PreparedChunk>,
    chunk: (BufWriter<File>, PathBuf, Sha256, u64),
    index: u32,
) -> AppResult<()> {
    let (mut writer, path, hasher, size) = chunk;
    writer.flush()?;
    chunks.push(PreparedChunk {
        path,
        index,
        size,
        sha256: hex::encode(hasher.finalize()),
        temporary: true,
    });
    Ok(())
}

fn prepare_plain_streaming(
    source: &Path,
    work_dir: &Path,
    max_chunk: u64,
    progress: &mut dyn FnMut(u64, u64) -> bool,
    on_chunk: &mut dyn FnMut(PreparedChunk) -> bool,
) -> AppResult<PreparedUploadMetadata> {
    let size = source.metadata()?.len();
    if size <= max_chunk {
        let hash = sha256_file_with_progress(source, progress)?;
        if !on_chunk(PreparedChunk {
            path: source.to_path_buf(),
            index: 0,
            size,
            sha256: hash.clone(),
            temporary: false,
        }) {
            return Err(AppError::Message("Transfer cancelled".into()));
        }
        return Ok(PreparedUploadMetadata {
            original_sha256: hash,
            wrapped_key: None,
            key_nonce: None,
        });
    }

    let mut reader = BufReader::with_capacity(BUFFER_BYTES, File::open(source)?);
    let mut original = Sha256::new();
    let mut buffer = vec![0u8; BUFFER_BYTES];
    let mut current: Option<(BufWriter<File>, PathBuf, Sha256, u64)> = None;
    let mut index = 0u32;
    let mut processed = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        original.update(&buffer[..read]);
        processed += read as u64;
        if !progress(processed, size) {
            return Err(AppError::Message("Transfer cancelled".into()));
        }
        let mut offset = 0;
        while offset < read {
            if current.is_none() {
                let path = work_dir.join(format!("part-{index:06}.tvchunk"));
                current = Some((
                    BufWriter::with_capacity(BUFFER_BYTES, File::create(&path)?),
                    path,
                    Sha256::new(),
                    0,
                ));
            }
            let (writer, _, hasher, written) = current.as_mut().unwrap();
            let available = (max_chunk - *written) as usize;
            let take = available.min(read - offset);
            writer.write_all(&buffer[offset..offset + take])?;
            hasher.update(&buffer[offset..offset + take]);
            *written += take as u64;
            offset += take;
            if *written == max_chunk {
                let chunk = finish_plain_streaming_chunk(current.take().unwrap(), index)?;
                if !on_chunk(chunk) {
                    return Err(AppError::Message("Transfer cancelled".into()));
                }
                index += 1;
            }
        }
    }
    if let Some(chunk) = current.take() {
        let chunk = finish_plain_streaming_chunk(chunk, index)?;
        if !on_chunk(chunk) {
            return Err(AppError::Message("Transfer cancelled".into()));
        }
    }
    Ok(PreparedUploadMetadata {
        original_sha256: hex::encode(original.finalize()),
        wrapped_key: None,
        key_nonce: None,
    })
}

fn finish_plain_streaming_chunk(
    chunk: (BufWriter<File>, PathBuf, Sha256, u64),
    index: u32,
) -> AppResult<PreparedChunk> {
    let (mut writer, path, hasher, size) = chunk;
    writer.flush()?;
    Ok(PreparedChunk {
        path,
        index,
        size,
        sha256: hex::encode(hasher.finalize()),
        temporary: true,
    })
}

fn prepare_encrypted_streaming(
    source: &Path,
    work_dir: &Path,
    master: &MasterKeyStore,
    max_chunk: u64,
    progress: &mut dyn FnMut(u64, u64) -> bool,
    on_chunk: &mut dyn FnMut(PreparedChunk) -> bool,
) -> AppResult<PreparedUploadMetadata> {
    if max_chunk < (ENCRYPTED_MAGIC.len() + 4 + 24 + 16 + 1) as u64 {
        return Err(AppError::Crypto("Chunk size is too small".into()));
    }
    let mut file_key = [0u8; 32];
    rand::rng().fill_bytes(&mut file_key);
    let cipher = XChaCha20Poly1305::new((&file_key).into());
    let (wrapped_key, key_nonce) = master.wrap_file_key(&file_key)?;
    let mut reader = BufReader::with_capacity(BUFFER_BYTES, File::open(source)?);
    let mut original = Sha256::new();
    let mut input = vec![0u8; BUFFER_BYTES.min((max_chunk / 2).max(1) as usize)];
    let mut current: Option<(BufWriter<File>, PathBuf, Sha256, u64)> = None;
    let mut index = 0u32;
    let total = source.metadata()?.len();
    let mut processed = 0u64;
    loop {
        let read = reader.read(&mut input)?;
        if read == 0 {
            break;
        }
        original.update(&input[..read]);
        processed += read as u64;
        if !progress(processed, total) {
            file_key.fill(0);
            return Err(AppError::Message("Transfer cancelled".into()));
        }
        let mut nonce = [0u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), &input[..read])
            .map_err(|_| AppError::Crypto("Unable to encrypt a file block".into()))?;
        let frame_size = 4 + nonce.len() + ciphertext.len();
        if current
            .as_ref()
            .map(|chunk| chunk.3 + frame_size as u64 > max_chunk)
            .unwrap_or(true)
        {
            if let Some(chunk) = current.take() {
                let chunk = finish_encrypted_streaming_chunk(chunk, index)?;
                if !on_chunk(chunk) {
                    file_key.fill(0);
                    return Err(AppError::Message("Transfer cancelled".into()));
                }
                index += 1;
            }
            let path = work_dir.join(format!("part-{index:06}.tve"));
            let mut writer = BufWriter::with_capacity(BUFFER_BYTES, File::create(&path)?);
            writer.write_all(ENCRYPTED_MAGIC)?;
            let mut hasher = Sha256::new();
            hasher.update(ENCRYPTED_MAGIC);
            current = Some((writer, path, hasher, ENCRYPTED_MAGIC.len() as u64));
        }
        let (writer, _, hasher, written) = current.as_mut().unwrap();
        let length = (read as u32).to_le_bytes();
        writer.write_all(&length)?;
        writer.write_all(&nonce)?;
        writer.write_all(&ciphertext)?;
        hasher.update(length);
        hasher.update(nonce);
        hasher.update(&ciphertext);
        *written += frame_size as u64;
    }
    if let Some(chunk) = current.take() {
        let chunk = finish_encrypted_streaming_chunk(chunk, index)?;
        if !on_chunk(chunk) {
            file_key.fill(0);
            return Err(AppError::Message("Transfer cancelled".into()));
        }
    } else {
        let path = work_dir.join("part-000000.tve");
        fs::write(&path, ENCRYPTED_MAGIC)?;
        if !on_chunk(PreparedChunk {
            path,
            index: 0,
            size: ENCRYPTED_MAGIC.len() as u64,
            sha256: hex::encode(Sha256::digest(ENCRYPTED_MAGIC)),
            temporary: true,
        }) {
            file_key.fill(0);
            return Err(AppError::Message("Transfer cancelled".into()));
        }
    }
    file_key.fill(0);
    Ok(PreparedUploadMetadata {
        original_sha256: hex::encode(original.finalize()),
        wrapped_key: Some(wrapped_key),
        key_nonce: Some(key_nonce),
    })
}

fn finish_encrypted_streaming_chunk(
    chunk: (BufWriter<File>, PathBuf, Sha256, u64),
    index: u32,
) -> AppResult<PreparedChunk> {
    let (mut writer, path, hasher, size) = chunk;
    writer.flush()?;
    Ok(PreparedChunk {
        path,
        index,
        size,
        sha256: hex::encode(hasher.finalize()),
        temporary: true,
    })
}

#[cfg(test)]
pub fn assemble_chunks(
    chunk_paths: &[PathBuf],
    output: &Path,
    encrypted: bool,
    file_key: Option<[u8; 32]>,
) -> AppResult<String> {
    let total = chunk_paths
        .iter()
        .filter_map(|path| path.metadata().ok().map(|metadata| metadata.len()))
        .sum();
    assemble_chunks_with_progress(
        chunk_paths,
        output,
        encrypted,
        file_key,
        total,
        false,
        |_, _| true,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn assemble_chunks_with_progress<F>(
    chunk_paths: &[PathBuf],
    output: &Path,
    encrypted: bool,
    file_key: Option<[u8; 32]>,
    total: u64,
    remove_inputs: bool,
    mut progress: F,
) -> AppResult<String>
where
    F: FnMut(u64, u64) -> bool,
{
    let mut writer = BufWriter::with_capacity(BUFFER_BYTES, File::create(output)?);
    let mut original = Sha256::new();
    let mut processed = 0u64;
    if encrypted {
        let key = file_key.ok_or_else(|| AppError::Crypto("Missing file decryption key".into()))?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        for path in chunk_paths {
            let mut reader = BufReader::with_capacity(BUFFER_BYTES, File::open(path)?);
            let mut magic = [0u8; 8];
            reader.read_exact(&mut magic)?;
            if &magic != ENCRYPTED_MAGIC {
                return Err(AppError::Crypto("Encrypted chunk header is invalid".into()));
            }
            loop {
                let mut length = [0u8; 4];
                match reader.read_exact(&mut length) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(error) => return Err(error.into()),
                }
                let plain_len = u32::from_le_bytes(length) as usize;
                let mut nonce = [0u8; 24];
                reader.read_exact(&mut nonce)?;
                let mut ciphertext = vec![0u8; plain_len + 16];
                reader.read_exact(&mut ciphertext)?;
                let plaintext = cipher
                    .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
                    .map_err(|_| {
                        AppError::Crypto(
                            "Chunk authentication failed; the file may be damaged".into(),
                        )
                    })?;
                writer.write_all(&plaintext)?;
                original.update(&plaintext);
                processed += plaintext.len() as u64;
                if !progress(processed, total) {
                    return Err(AppError::Message("Transfer cancelled".into()));
                }
            }
            if remove_inputs {
                let _ = fs::remove_file(path);
            }
        }
    } else {
        let mut buffer = vec![0u8; BUFFER_BYTES];
        for path in chunk_paths {
            let mut reader = BufReader::with_capacity(BUFFER_BYTES, File::open(path)?);
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                writer.write_all(&buffer[..read])?;
                original.update(&buffer[..read]);
                processed += read as u64;
                if !progress(processed, total) {
                    return Err(AppError::Message("Transfer cancelled".into()));
                }
            }
            if remove_inputs {
                let _ = fs::remove_file(path);
            }
        }
    }
    writer.flush()?;
    Ok(hex::encode(original.finalize()))
}

pub fn sha256_file(path: &Path) -> AppResult<String> {
    sha256_file_with_progress(path, &mut |_, _| true)
}

pub fn sha256_file_with_progress(
    path: &Path,
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> AppResult<String> {
    let mut reader = BufReader::with_capacity(BUFFER_BYTES, File::open(path)?);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; BUFFER_BYTES];
    let total = path.metadata()?.len();
    let mut processed = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        processed += read as u64;
        if !progress(processed, total) {
            return Err(AppError::Message("Transfer cancelled".into()));
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_streaming_keeps_only_the_current_part_on_disk() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.bin");
        let work = temp.path().join("work");
        let payload: Vec<u8> = (0..2_500_000).map(|i| (i % 251) as u8).collect();
        fs::write(&source, &payload).unwrap();
        fs::create_dir(&work).unwrap();

        let mut seen = 0;
        let mut max_parts_on_disk = 0;
        let metadata =
            prepare_plain_streaming(&source, &work, 700_000, &mut |_, _| true, &mut |chunk| {
                seen += 1;
                max_parts_on_disk = max_parts_on_disk.max(fs::read_dir(&work).unwrap().count());
                assert!(chunk.temporary);
                fs::remove_file(chunk.path).unwrap();
                true
            })
            .unwrap();

        assert_eq!(seen, 4);
        assert_eq!(max_parts_on_disk, 1);
        assert_eq!(fs::read_dir(&work).unwrap().count(), 0);
        assert_eq!(metadata.original_sha256, sha256_file(&source).unwrap());
    }

    #[test]
    fn encrypted_round_trip_across_chunks() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        let master = MasterKeyStore::load_or_create_for_test(&data_dir).unwrap();
        let source = temp.path().join("source.bin");
        let payload: Vec<u8> = (0..2_500_000).map(|i| (i % 251) as u8).collect();
        fs::write(&source, &payload).unwrap();
        let prepared =
            prepare_with_limit(&source, &temp.path().join("work"), true, &master, 700_000).unwrap();
        assert!(prepared.chunks.len() > 1);
        assert_eq!(prepared.original_sha256, sha256_file(&source).unwrap());
        let key = master
            .unwrap_file_key(
                prepared.wrapped_key.as_ref().unwrap(),
                prepared.key_nonce.as_ref().unwrap(),
            )
            .unwrap();
        let output = temp.path().join("output.bin");
        assemble_chunks(
            &prepared
                .chunks
                .iter()
                .map(|c| c.path.clone())
                .collect::<Vec<_>>(),
            &output,
            true,
            Some(key),
        )
        .unwrap();
        assert_eq!(fs::read(output).unwrap(), payload);
    }

    #[test]
    fn preview_frame_size_and_authentication_are_checked() {
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let plaintext = vec![42u8; 123_456];
        let cipher = XChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext);

        assert_eq!(decrypt_encrypted_frame(&frame, &key).unwrap(), plaintext);
        assert_eq!(
            encrypted_chunk_plain_size(ENCRYPTED_MAGIC_BYTES + frame.len() as u64).unwrap(),
            123_456
        );
        frame[30] ^= 1;
        assert!(decrypt_encrypted_frame(&frame, &key).is_err());
    }
}
