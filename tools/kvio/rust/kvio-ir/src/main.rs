// SPDX-License-Identifier: Apache-2.0

use kvio_ir::{validate_translation, Constraints, SourceCertificate, Workload};
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

fn usage() -> &'static str {
    "usage: kvio-ir certify BUNDLE [--region-bytes N] \
[--max-transfer-bytes N] [--output FILE]"
}

fn parse_u64(value: Option<String>, option: &str) -> Result<u64, Box<dyn Error>> {
    let text = value.ok_or_else(|| format!("{option} requires a value"))?;
    Ok(text
        .parse()
        .map_err(|_| format!("invalid {option}: {text}"))?)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Box<dyn Error>> {
    let data = fs::read(path)?;
    Ok(serde_json::from_slice(&data)?)
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    let action = arguments.next();
    if matches!(action.as_deref(), Some("-h" | "--help")) {
        println!("{}", usage());
        return Ok(());
    }
    if action.as_deref() != Some("certify") {
        return Err(usage().into());
    }
    let bundle_arg = arguments.next().ok_or_else(usage)?;
    if matches!(bundle_arg.as_str(), "-h" | "--help") {
        println!("{}", usage());
        return Ok(());
    }
    let bundle = PathBuf::from(bundle_arg);
    let mut constraints = Constraints::default();
    let mut output = None;
    while let Some(option) = arguments.next() {
        match option.as_str() {
            "--region-bytes" => {
                constraints.region_bytes = Some(parse_u64(arguments.next(), &option)?);
            }
            "--max-transfer-bytes" => {
                constraints.max_transfer_bytes = Some(parse_u64(arguments.next(), &option)?);
            }
            "--output" => {
                output = Some(PathBuf::from(
                    arguments.next().ok_or("--output requires a value")?,
                ));
            }
            "-h" | "--help" => {
                println!("{}", usage());
                return Ok(());
            }
            _ => return Err(format!("unknown option {option}\n{}", usage()).into()),
        }
    }

    let workload: Workload = read_json(&bundle.join("workload.json"))?;
    let source: SourceCertificate = read_json(&bundle.join("certificate.json"))?;
    let iolog = fs::read_to_string(bundle.join("commands.iolog"))?;
    let certificate = validate_translation(&workload, &iolog, &source, constraints)?;
    let json = serde_json::to_string_pretty(&certificate)? + "\n";
    if let Some(path) = output {
        fs::write(path, json)?;
    } else {
        print!("{json}");
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("kvio-ir: {error}");
        std::process::exit(2);
    }
}
