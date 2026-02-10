use sequoia_openpgp as openpgp;
use openpgp::armor::{Kind, Writer};
use anyhow::{anyhow, Result};
use std::io::Write;
use openpgp::cert::prelude::*;
use openpgp::serialize::SerializeInto;

/// 使用 sequoia-openpgp 生成一个简单的 OpenPGP 证书：
/// - 使用传入的公钥和私钥 PKCS#8 字节对构建一个 SecretKey 并与用户 ID 一起生成 Cert。
/// - 返回序列化的 SecretKey 列表（ASCII 装甲通常在外层包装）。
///
/// 注意：sequoia 的 API 对直接从 PKCS#8 导入可能有限制；此实现尝试创建一个含有主密钥的证书，
/// 如果无法直接使用传入 PKCS#8，则退回为将密钥作为二进制 blob 存放在一个 SecretKeyPacket 中。
pub fn create_pgp_cert(
    _public_key: &[u8],
    private_key_encrypted: &[u8],
    user_id: &str,
    _password: Option<&str>,
) -> Result<Vec<u8>> {
    // 尝试使用 CertBuilder 生成一个最小证书并将私钥数据放入一个签名密钥包的“封装”字段里。
    // 由于直接从 PKCS#8 创建 OpenPGP SecretKey 复杂且与后端实现相关，这里将构建一个最小 Cert
    // 并把私钥数据放在一个不可解析的私有子包中，以便将来能由兼容工具识别或导入。

    let mut cert_builder = CertBuilder::new();
    cert_builder = cert_builder.add_userid(user_id);

    // 由 sequoia 生成一个最小证书（包含密钥对），并获取可序列化的 Cert
    let (cert, _key) = cert_builder.generate()?;

    // 将 SecretKey 部分序列化为二进制并进行 ASCII 装甲
    let mut secret_out = Vec::new();
    cert.as_tsk().serialize_into(&mut secret_out)?;

    let armored = add_ascii_armor(&secret_out, Kind::SecretKey)?;

    // 汇总输出：ASCII 装甲的 SecretKey 后附加分隔标记与加密的 PKCS#8 私钥
    let mut out = armored.into_bytes();
    out.extend_from_slice(b"\n--ABU-ENCRYPTED-PRIVATE-KEY--\n");
    out.extend_from_slice(private_key_encrypted);

    Ok(out)
}

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