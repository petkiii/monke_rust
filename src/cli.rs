use std::path::PathBuf;

use clap::{command, Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Unpacking and packing BTD6 save file.", long_about = None)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    Pack {
        packed_path: PathBuf,
        output_path: PathBuf,
    },
    Unpack {
        unpacked_path: PathBuf,
        output_path: PathBuf,
    },
}