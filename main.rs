use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use fastpbkdf2::pbkdf2_hmac_sha512;
use hex::decode;
use std::env;

use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

fn main() {
    // // amw data
    let data = decode("899177790da6432f4482fffe6f25685ed0a96d5f965a49bd0981e45a010a094cc4dbcdbf6048577466cf8243c47ebda96a22549b5f1a2d7ad72c3cf864407c6bebd567c0e998398d5c8a5e0fcdac923db24cf276395d6b8af3e4d17fdb5749cb3e2477e897ed6c79b0134a4e6c296ccb1cb3d0d60d02114c5d7f376f553c57ceb368a0eb34b1a01da103b380edeac1e93e8e31bc76beb0dda7cbb027e269bf96481d4df8d0d08a6e8f998f04bd6ff4978be07a19713063572f65d2c02c753085693d1389b119a863224f3e6de381b70d869cc3c5f6a6a381689c18cc18a1d8dc6f").unwrap();
    let password = b"password1234";

    // Get the command-line arguments
    let args: Vec<String> = env::args().collect();

    // // Check if the password argument is provided
    // if args.len() < 2 {
    //     eprintln!("Usage: {} <password>", args[0]);
    //     std::process::exit(1);
    // }
    //
    // // Get the password from the command-line arguments
    // let password = &args[1];

    let salt = &data[SALT_START..SALT_END];
    let nonce = &data[NONCE_START..NONCE_END];
    let tag = &data[TAG_START..TAG_END];
    let encr_data = &data[ENCRYPTED_START..];

    let mut msg = vec![0u8; encr_data.len() + TAG_SIZE];
    msg[..encr_data.len()].copy_from_slice(encr_data);
    msg[encr_data.len()..].copy_from_slice(tag);

    let nonce = Nonce::from_slice(nonce);

    // Simple single test
    let payload = Payload::from(msg.as_slice());
    let result = decrypt_with_password(password.as_ref(), salt, &nonce, payload);
    match result {
        Ok(res) => {
            println!("Result: {}", res);
        }
        Err(err) => {
            println!("Error: decryption failed: {:?}", err);
        }
    }

    // let password_generator = Arc::new(Mutex::new(PasswordGenerator::new()));
    // (0u128..u128::MAX).into_par_iter().for_each(|iteration| {
    //     let password = {
    //         let mut password_generator = password_generator.lock().unwrap();
    //         password_generator.next()
    //     };
    //     match password {
    //         Some(password) => {
    //             if iteration % 1000 == 0 {
    //                 println!("Password: {}", password);
    //             }
    //             let password_bytes = password.as_bytes();
    //             let result = decrypt_with_password(
    //                 password_bytes,
    //                 &salt,
    //                 &nonce,
    //                 Payload::from(msg.as_slice()),
    //             );
    //             match result {
    //                 Ok(res) => {
    //                     println!("Result: {} -> {}", password, res);
    //                     std::process::exit(0);
    //                 }
    //                 Err(_) => {
    //                     // do nothing
    //                 }
    //             }
    //         }
    //         None => {
    //             // do nothing
    //             std::process::exit(0);
    //         }
    //     }
    // });
}

struct PasswordGenerator {
    charset: Vec<u8>,
    current_length: usize,
    max_length: usize,
    indices: Vec<usize>,
}

impl PasswordGenerator {
    fn new() -> Self {
        PasswordGenerator {
            charset: (b'!'..=b'~').collect(),
            current_length: 6,
            max_length: 16,
            indices: vec![0; 6],
        }
    }
}

impl Iterator for PasswordGenerator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.indices.is_empty() {
            return None;
        }

        let password: String = self
            .indices
            .iter()
            .map(|&i| self.charset[i] as char)
            .collect();

        for i in (0..self.indices.len()).rev() {
            if self.indices[i] < self.charset.len() - 1 {
                self.indices[i] += 1;
                return Some(password);
            } else {
                self.indices[i] = 0;
                if i == 0 {
                    if self.current_length < self.max_length {
                        self.current_length += 1;
                        self.indices = vec![0; self.current_length];
                    } else {
                        self.indices.clear();
                    }
                }
            }
        }

        Some(password)
    }
}

const ITER_V2: u32 = 210012; // https://en.wikipedia.org/wiki/PBKDF2
const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;
const TAG_SIZE: usize = 16;
// const METADATA_SIZE: usize = SALT_SIZE + NONCE_SIZE + TAG_SIZE;
const SALT_START: usize = 0;
const SALT_END: usize = SALT_START + SALT_SIZE;
const NONCE_START: usize = SALT_END;
const NONCE_END: usize = NONCE_START + NONCE_SIZE;
const TAG_START: usize = NONCE_END;
const TAG_END: usize = TAG_START + TAG_SIZE;
const ENCRYPTED_START: usize = TAG_END;

fn decrypt_with_password(
    password: &[u8],
    salt: &[u8],
    nonce: &Nonce,
    payload: Payload,
) -> Result<String, aead::Error> {
    let key = derive_key(password, salt, ITER_V2, KEY_SIZE);
    let key = Key::from_slice(key.as_slice());
    let cha = ChaCha20Poly1305::new(key);

    let res = cha.decrypt(nonce, payload);

    match res {
        Ok(res) => Ok(String::from_utf8(res).unwrap()),
        Err(err) => Err(err),
    }
}

fn derive_key(password: &[u8], salt: &[u8], iterations: u32, key_length: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_length];
    pbkdf2_hmac_sha512(password, salt, iterations, &mut key);
    key
}
