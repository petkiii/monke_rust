use std::{
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use clap::{arg, command, Parser, Subcommand};
use flate2::{bufread::ZlibDecoder, write::ZlibEncoder, Compression};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha1::Sha1;

#[derive(Parser)]
#[command(version, about = "Unpacking and packing BTD6 save file.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Pack { input: String, output: String },
    Unpack { input: String, output: String },
}
// monke pack <json file> <output save>
// monke unpack <save file> <output json>
fn main() -> Result<(), Box<dyn Error>> {
    // let packed = "C:\\Program Files (x86)\\Steam\\userdata\\1515958253\\960090\\local\\link\\PRODUCTION\\current\\Profile.Save";

    let cli = Cli::parse();

    match &cli.command {
        Commands::Pack { input, output } => {
            pack(input, output)?;
        }
        Commands::Unpack { input, output } => {
            let save_info = get_save_info(input)?;
            unpack(&save_info, output)?;
        }
    };

    // let save_info = get_save_info(&".\\Profile.Save".to_string())?;
    // unpack(&save_info, &"unpacked1.json".to_string())?;

    // pack(
    //     &save_info,
    //     &"unpacked.json".to_string(),
    //     &".\\Profile.Save.bin".to_string(),
    // )?;
    // unpack(&save_info, &unpacked.to_string())?;
    // let save_info = get_save_info(&".\\packed.bin".to_string())?;
    Ok(())
}

const PASSWORD: &[u8; 2] = b"11";

fn derive_key(salt: [u8; 24]) -> ([u8; 16], [u8; 16]) {
    let mut derived_key = [0 as u8; 32];
    pbkdf2_hmac::<Sha1>(PASSWORD, &salt, 10, &mut derived_key);

    // let key  = &derived_key[16..];
    // let iv = &derived_key[..16];

    let (iv, key) = derived_key.split_at(16);

    let mut key_out = [0; 16];
    let mut iv_out = [0; 16];

    key_out.copy_from_slice(key);
    iv_out.copy_from_slice(iv);

    return (key_out, iv_out);
}

fn pack(
    // save_info: &SaveInfo,
    unpacked_path: &String,
    save_path: &String,
) -> Result<(), Box<dyn Error>> {
    // Write boilerplate
    let mut save_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&save_path)?;
    // save_file.write(&save_info.header)?;
    // save_file.write(&save_info.password_index)?;
    // save_file.write(&save_info.salt)?;
    let mut salt = [0; 24];
    rand::thread_rng().fill_bytes(&mut salt);
    save_file.write(&[0; 44])?;
    save_file.write(&(2 as u64).to_be_bytes())?;
    save_file.write(&salt)?;

    // Generate key and iv
    let mut derived_key = [0 as u8; 16 + 16];
    pbkdf2_hmac::<Sha1>(PASSWORD, &salt, 10, &mut derived_key);

    // Create encryptor
    let key = &derived_key[16..];
    let iv = &derived_key[..16];
    let encryptor = cbc::Encryptor::<aes::Aes128>::new(key.into(), iv.into());

    // Read content
    let mut unpacked_file = File::open(unpacked_path)?;
    let mut data = Vec::new();
    unpacked_file.read_to_end(&mut data)?;

    // Encode with zlib
    let mut encoded: Vec<u8> = Vec::new();
    let mut encoder = ZlibEncoder::new(&mut encoded, Compression::new(3));
    encoder.write_all(&mut data)?;
    drop(encoder);

    let encrypted = encryptor.encrypt_padded_vec_mut::<Pkcs7>(&encoded);

    save_file.write(&encrypted)?;
    save_file.flush()?;

    return Ok(());
}

struct SaveInfo {
    header: [u8; 44],
    password_index: [u8; 8],
    salt: [u8; 24],
    data: Vec<u8>,
}

fn get_save_info(path: &String) -> Result<SaveInfo, Box<dyn Error>> {
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

fn unpack(save_info: &SaveInfo, save_path: &String) -> Result<(), Box<dyn Error>> {
    let mut derived_key = [0 as u8; 16 + 16];
    pbkdf2_hmac::<Sha1>(PASSWORD, &save_info.salt, 10, &mut derived_key);

    let key = &derived_key[16..];
    let iv = &derived_key[..16];
    let decryptor = cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into());

    let decrypted = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&save_info.data)
        .unwrap();

    let mut decoded: Vec<u8> = Vec::new();
    let mut decoder = ZlibDecoder::new(&decrypted[..]);
    decoder.read_to_end(&mut decoded)?;

    fs::write(save_path, &decoded).unwrap();

    return Ok(());
}
