use crate::error::{AppError, AppResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct MasterKeyStore {
    path: PathBuf,
    key: [u8; 32],
    keychain_backed: bool,
}

impl MasterKeyStore {
    #[cfg(test)]
    pub fn load_or_create_for_test(data_dir: impl AsRef<Path>) -> AppResult<Self> {
        let path = data_dir.as_ref().join("vault.test.key");
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        fs::write(&path, key)?;
        set_private_permissions(&path)?;
        Ok(Self {
            path,
            key,
            keychain_backed: false,
        })
    }

    pub fn load_or_create(data_dir: impl AsRef<Path>) -> AppResult<Self> {
        let path = data_dir.as_ref().join("vault.key");
        let marker = data_dir.as_ref().join("vault.keychain");
        let keychain = keyring::Entry::new("app.televault.desktop", "vault-master-key").ok();

        if marker.exists() {
            let encoded = keychain
                .as_ref()
                .ok_or_else(|| AppError::Crypto("The operating-system keychain is unavailable".into()))?
                .get_password()
                .map_err(|_| AppError::Crypto("TeleVault could not read its recovery key from the operating-system keychain".into()))?;
            let key = decode_key(&encoded)?;
            return Ok(Self {
                path,
                key,
                keychain_backed: true,
            });
        }

        if !path.exists() {
            if let Some(entry) = keychain.as_ref() {
                if let Ok(encoded) = entry.get_password() {
                    if let Ok(key) = decode_key(&encoded) {
                        fs::write(&marker, b"keyring-v1")?;
                        set_private_permissions(&marker)?;
                        return Ok(Self {
                            path,
                            key,
                            keychain_backed: true,
                        });
                    }
                }
            }
        }

        let mut key = if path.exists() {
            let bytes = fs::read(&path)?;
            bytes
                .try_into()
                .map_err(|_| AppError::Crypto("The local vault key is invalid".into()))?
        } else {
            let mut generated = [0u8; 32];
            rand::rng().fill_bytes(&mut generated);
            generated
        };

        if let Some(entry) = keychain {
            let encoded = URL_SAFE_NO_PAD.encode(key);
            if entry.set_password(&encoded).is_ok()
                && entry.get_password().ok().as_deref() == Some(encoded.as_str())
            {
                fs::write(&marker, b"keyring-v1")?;
                set_private_permissions(&marker)?;
                if path.exists() {
                    fs::remove_file(&path)?;
                }
                return Ok(Self {
                    path,
                    key,
                    keychain_backed: true,
                });
            }
        }

        if !path.exists() {
            fs::write(&path, key)?;
        }
        set_private_permissions(&path)?;
        let result = Self {
            path,
            key,
            keychain_backed: false,
        };
        key.zeroize();
        Ok(result)
    }

    pub fn is_ready(&self) -> bool {
        self.keychain_backed || self.path.exists()
    }
    pub fn keychain_backed(&self) -> bool {
        self.keychain_backed
    }
    pub fn export_recovery(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key)
    }

    pub fn verify_recovery(&self, candidate: &str) -> bool {
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(candidate.trim()) else {
            return false;
        };
        if decoded.len() != self.key.len() {
            return false;
        }
        let mut difference = 0u8;
        for (left, right) in decoded.iter().zip(self.key.iter()) {
            difference |= left ^ right;
        }
        let mut decoded = decoded;
        decoded.zeroize();
        difference == 0
    }

    pub fn wrap_file_key(&self, file_key: &[u8; 32]) -> AppResult<(String, String)> {
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let mut nonce = [0u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let wrapped = cipher
            .encrypt(XNonce::from_slice(&nonce), file_key.as_ref())
            .map_err(|_| AppError::Crypto("Could not protect the file key".into()))?;
        Ok((
            URL_SAFE_NO_PAD.encode(wrapped),
            URL_SAFE_NO_PAD.encode(nonce),
        ))
    }

    pub fn unwrap_file_key(&self, wrapped: &str, nonce: &str) -> AppResult<[u8; 32]> {
        let wrapped = URL_SAFE_NO_PAD
            .decode(wrapped)
            .map_err(|_| AppError::Crypto("Invalid wrapped key".into()))?;
        let nonce = URL_SAFE_NO_PAD
            .decode(nonce)
            .map_err(|_| AppError::Crypto("Invalid key nonce".into()))?;
        if nonce.len() != 24 {
            return Err(AppError::Crypto("Invalid key nonce length".into()));
        }
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let plain = cipher
            .decrypt(XNonce::from_slice(&nonce), wrapped.as_ref())
            .map_err(|_| AppError::Crypto("The recovery key cannot unlock this file".into()))?;
        plain
            .try_into()
            .map_err(|_| AppError::Crypto("Invalid file key length".into()))
    }

    pub fn seal_metadata(&self, plaintext: &[u8]) -> AppResult<(String, String)> {
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let mut nonce = [0u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let sealed = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| AppError::Crypto("Could not protect private file metadata".into()))?;
        Ok((
            URL_SAFE_NO_PAD.encode(sealed),
            URL_SAFE_NO_PAD.encode(nonce),
        ))
    }

    pub fn open_metadata(&self, sealed: &str, nonce: &str) -> AppResult<Vec<u8>> {
        let sealed = URL_SAFE_NO_PAD
            .decode(sealed)
            .map_err(|_| AppError::Crypto("Invalid private metadata".into()))?;
        let nonce = URL_SAFE_NO_PAD
            .decode(nonce)
            .map_err(|_| AppError::Crypto("Invalid private metadata nonce".into()))?;
        if nonce.len() != 24 {
            return Err(AppError::Crypto(
                "Invalid private metadata nonce length".into(),
            ));
        }
        XChaCha20Poly1305::new((&self.key).into())
            .decrypt(XNonce::from_slice(&nonce), sealed.as_ref())
            .map_err(|_| AppError::Crypto("The recovery key cannot open private metadata".into()))
    }
}

fn decode_key(encoded: &str) -> AppResult<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AppError::Crypto("The keychain recovery key is invalid".into()))?
        .try_into()
        .map_err(|_| AppError::Crypto("The keychain recovery key has an invalid length".into()))
}

fn set_private_permissions(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exported_recovery_key_is_verified_without_accepting_malformed_keys() {
        let temp = tempfile::tempdir().unwrap();
        let store = MasterKeyStore::load_or_create_for_test(temp.path()).unwrap();
        assert!(store.verify_recovery(&store.export_recovery()));
        assert!(store.verify_recovery(&format!("  {}  ", store.export_recovery())));
        assert!(!store.verify_recovery("not-a-recovery-key"));
        let mut different = store.export_recovery();
        different.replace_range(0..1, if &different[0..1] == "A" { "B" } else { "A" });
        assert!(!store.verify_recovery(&different));
    }
}
