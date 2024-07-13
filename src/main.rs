#[macro_use]
mod error;
mod cli;

use crate::error::MonkeError;

use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use clap::Parser;
use cli::{Cli, Commands};
use flate2::{bufread::ZlibDecoder, write::ZlibEncoder, Compression};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde_json::Value;
use sha1::Sha1;

type ResultOrError<T> = Result<T, Box<dyn Error>>;

const PASSWORD: &[u8; 2] = b"11";
const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

fn check_equal(first: &PathBuf, second: &PathBuf) -> ResultOrError<()> {
    if first == second {
        return Err(monke_error!(
            "Input cannot be equal to Output ('{}' == '{}').",
            first.display(),
            second.display()
        ));
    }

    return Ok(());
}
fn main() -> ResultOrError<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Pack {
            packed_path: input,
            output_path: output,
        } => {
            check_equal(input, output)?;
            pack(input, output)?;
        }
        Commands::Unpack {
            unpacked_path: input,
            output_path: output,
        } => {
            check_equal(input, output)?;
            unpack(&input, output)?;
        }
    };
    Ok(())
}

fn derive_key(salt: &[u8; 24]) -> ([u8; 16], [u8; 16]) {
    let mut derived_key = [0 as u8; 32];
    pbkdf2_hmac::<Sha1>(PASSWORD, salt, 10, &mut derived_key);

    let (iv, key) = derived_key.split_at(16);

    let mut key_out = [0; 16];
    let mut iv_out = [0; 16];

    key_out.copy_from_slice(key);
    iv_out.copy_from_slice(iv);

    return (key_out, iv_out);
}

fn pack(unpacked_path: &PathBuf, output_path: &PathBuf) -> ResultOrError<()> {
    // Open file for writing
    let mut output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output_path)?;

    // Write boilerplate
    let mut salt = [0; 24];
    rand::thread_rng().fill_bytes(&mut salt);
    output_file.write(&[0; 44])?;
    output_file.write(&(2 as u64).to_le_bytes())?;
    output_file.write(&salt)?;

    // Read content
    let mut unpacked_file = File::open(unpacked_path)?;
    let mut data = Vec::new();
    unpacked_file.read_to_end(&mut data)?;

    // Parse json and minify it
    let json = parse_json(&data)?;
    let minified = serde_json::to_string(&json)?;

    // Add BOM
    // let mut data = [BOM, minified.as_bytes()].concat();

    // Works without adding BOM
    let mut data = minified.as_bytes();

    // Encode with zlib
    let mut encoded: Vec<u8> = Vec::new();
    let mut encoder = ZlibEncoder::new(&mut encoded, Compression::new(3));
    encoder.write_all(&mut data)?;
    drop(encoder);

    // Generate key and iv
    let (key, iv) = derive_key(&salt);

    // Create encryptor
    let encryptor = cbc::Encryptor::<aes::Aes128>::new(&key.into(), &iv.into());

    // Encrypt data
    let encrypted = encryptor.encrypt_padded_vec_mut::<Pkcs7>(&encoded);

    // Write data to output
    output_file.write(&encrypted)?;
    output_file.flush()?;

    return Ok(());
}

#[allow(dead_code)]
struct SaveInfo {
    header: [u8; 44],
    password_index: [u8; 8],
    salt: [u8; 24],
    data: Vec<u8>,
}

fn get_save_info(path: &PathBuf) -> ResultOrError<SaveInfo> {
    let mut file = File::open(path).unwrap();

    let mut header = [0; 44];
    file.read_exact(&mut header)?;

    let mut password_index = [0; 8];
    file.read_exact(&mut password_index)?;

    let mut salt = [0; 24];
    file.read_exact(&mut salt)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    return Ok(SaveInfo {
        header,
        password_index,
        salt,
        data,
    });
}

fn unpack(packed_path: &PathBuf, output_path: &PathBuf) -> ResultOrError<()> {
    let save_info = get_save_info(packed_path)?;

    let (key, iv) = derive_key(&save_info.salt);
    let decryptor = cbc::Decryptor::<aes::Aes128>::new(&key.into(), &iv.into());

    let decrypted = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&save_info.data)
        .unwrap();

    let mut decoded: Vec<u8> = Vec::new();
    let mut decoder = ZlibDecoder::new(&decrypted[..]);
    decoder.read_to_end(&mut decoded)?;

    let json: Value = parse_json(&decoded)?;
    let pretty_text = serde_json::to_string_pretty(&json)?;

    fs::write(output_path, &pretty_text).unwrap();

    return Ok(());
}

fn parse_json(bytes: &[u8]) -> ResultOrError<Value> {
    let bytes_without_bom = if bytes.starts_with(BOM) {
        &bytes[3..]
    } else {
        &bytes
    };
    let data: Value = serde_json::from_slice(&bytes_without_bom)?;

    return Ok(data);
}
