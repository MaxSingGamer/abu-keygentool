use sequoia_openpgp as openpgp;
use openpgp::armor::{Kind, Writer};
use anyhow::{anyhow, Result};
use std::io::Write;

/// 添加ASCII装甲封装
pub fn add_ascii_armor(data: &[u8], kind: Kind) -> Result<String> {
    let mut armored = Vec::new();
    {
        let mut writer = Writer::new(&mut armored, kind)?;
        writer.write_all(data)?;
        writer.finalize()?;
    }

    String::from_utf8(armored).map_err(|e| anyhow!("Failed to convert armor to string: {:?}", e))
}

#[allow(dead_code)]
pub fn export_pkcs8(public_key: &[u8], private_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    Ok((public_key.to_vec(), private_key.to_vec()))
}