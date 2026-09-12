use crate::MyApp;
use crate::PathBuf;
use argon2::{
    Argon2, Params,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Write, prelude::*};

use serde::{Deserialize, Serialize};

pub struct EncryptedEntry {
    pub title: String,
    pub encrypted_json: Vec<u8>,
    pub nonce: [u8; 12],
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct Entry {
    pub title: String,
    pub username: String,
    pub password: String,
}

impl Entry {
    pub fn new(title: String, username: String, password: String) -> Self {
        Entry {
            title,
            username,
            password,
        }
    }
}

pub fn create_db(password: &String, file_path: &PathBuf) -> Key {
    //let full_path = format!("{}/{}.enc", file_path_string, name);
    //let path = file_path.as_ref().expect("no file path provided");

    let salt = SaltString::generate(&mut OsRng);
    let salt_bytes = salt.as_str().as_bytes();
    let mut file = File::create(file_path).expect("error");

    let mut key_bytes = [0u8; 32];

    //CHANGE SO USER CAN PICK
    let params = Params::new(
        16000, // Memory cost in KiB
        160,   // Iterations
        1,     // Parallelism
        None,
    )
    .expect("Invalid params");

    let argon2 = Argon2::new(argon2::Algorithm::Argon2d, argon2::Version::V0x13, params);
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("hash making error")
        .to_string();

    writeln!(file, "{}", password_hash).expect("Failed to write hash");

    argon2
        .hash_password_into(password.as_bytes(), &salt_bytes, &mut key_bytes)
        .expect("key make fail");

    *Key::from_slice(&key_bytes)
}

pub fn unlock_db(
    password: &String,
    file_path: &Option<PathBuf>,
) -> Result<Key, Box<dyn std::error::Error>> {
    let path = match file_path.as_ref() {
        Some(p) => p,
        None => return Err("No file path selected".into()),
    };

    let file = File::open(path).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(file);

    let mut first_line = String::new();
    reader
        .read_line(&mut first_line)
        .map_err(|e| e.to_string())?;

    let hash_str = first_line.trim();

    let parsed_hash = match PasswordHash::new(hash_str) {
        Ok(h) => h,
        Err(_) => return Err("Invalid password hash format".into()),
    };

    let params = Params::new(16000, 160, 1, None).unwrap();
    let argon2 = Argon2::new(argon2::Algorithm::Argon2d, argon2::Version::V0x13, params);

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => {}
        Err(_) => return Err("Invalid password".into()),
    }

    let salt = parsed_hash.salt.ok_or("No salt found in hash")?;
    let salt_bytes = salt.as_str().as_bytes();

    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt_bytes, &mut key_bytes)
        .map_err(|e| e.to_string())?;

    Ok(Key::from(key_bytes))
}

impl MyApp {
    pub fn encrypted_payload_to_entry(&self, index: usize) -> Entry {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&self.loaded_entries[index].nonce),
                self.loaded_entries[index].encrypted_json.as_ref(),
            )
            .expect("Decryption failed");

        let entry: Entry = serde_json::from_slice(&plaintext).expect("Failed to deserialize entry");

        entry
    }
    pub fn create_new_entry(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref path) = self.file_path {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            let mut lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

            let payload_bytes = serde_json::to_vec(&self.new_entry)?;
            let cipher = ChaCha20Poly1305::new(&self.key);
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let cipher_payload = cipher.encrypt(&nonce, payload_bytes.as_ref());

            let payload_hex = hex::encode(cipher_payload.unwrap());
            let nonce_hex = hex::encode(nonce);

            lines.push(format!("{}:{}", payload_hex, nonce_hex));

            let temp_path = format!("{}.tmp", path.display());
            {
                let mut temp_file = File::create(&temp_path)?;
                for line in &lines {
                    writeln!(temp_file, "{}", line)?;
                }
            }

            std::fs::rename(&temp_path, path)?;

            Ok(())
        } else {
            Err("No file path selected!".into())
        }
    }
    pub fn decrypt_all_entries(&mut self) {
        if let Some(ref path) = self.file_path {
            match OpenOptions::new().read(true).open(path) {
                Ok(file) => {
                    let reader = BufReader::new(file);
                    let mut lines = reader.lines();

                    lines.next(); // skips reading argon2 hash

                    let cipher = ChaCha20Poly1305::new(&self.key);
                    for line_result in lines {
                        let line = line_result.unwrap();

                        let parts: Vec<&str> = line.split(':').collect();

                        if parts.len() == 2 {
                            let payload_hex = parts[0];
                            let nonce_hex = parts[1];

                            let payload_bytes = hex::decode(payload_hex).unwrap();
                            let nonce_bytes = hex::decode(nonce_hex).unwrap();

                            let nonce_array: &[u8; 12] = nonce_bytes
                                .as_slice()
                                .try_into()
                                .expect("Invalid nonce length");
                            let nonce = chacha20poly1305::Nonce::from_slice(nonce_array);

                            // only decrypt title, decrypt password if user really wants to see it
                            let plaintext_title = cipher
                                .decrypt(nonce, payload_bytes.as_ref())
                                .expect("Decryption failed");

                            let loaded_entry: Entry = serde_json::from_slice(&plaintext_title)
                                .expect("Failed to deserialize entry");

                            let secure_entry = EncryptedEntry {
                                title: loaded_entry.title,
                                encrypted_json: payload_bytes,
                                nonce: *nonce_array,
                            };

                            self.loaded_entries.push(secure_entry);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to open file: {}", e);
                }
            }
        } else {
            eprintln!("No file path selected!");
        }
    }
    pub fn update_entry(
        &mut self,
        index: usize,
        updated_entry: Entry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref path) = self.file_path {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            let mut lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

            if index + 1 >= lines.len() {
                return Err("Entry index out of bounds".into());
            }

            let payload_bytes = serde_json::to_vec(&updated_entry)?;
            let cipher = ChaCha20Poly1305::new(&self.key);
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let cipher_payload = cipher.encrypt(&nonce, payload_bytes.as_ref());

            let payload_hex = hex::encode(cipher_payload.unwrap());
            let nonce_hex = hex::encode(nonce);

            lines[index + 1] = format!("{}:{}", payload_hex, nonce_hex);

            let temp_path = format!("{}.tmp", path.display());
            {
                let mut temp_file = File::create(&temp_path)?;
                for line in &lines {
                    writeln!(temp_file, "{}", line)?;
                }
            }
            std::fs::rename(&temp_path, path)?;

            Ok(())
        } else {
            Err("No file path selected".into())
        }
    }
}
