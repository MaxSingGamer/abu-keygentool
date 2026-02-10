pub mod encryption;

use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::serialize::SerializeInto;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 安全密钥容器 - 封装由 sequoia 生成的 Cert，并保存可序列化的 secret/public 表示
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    /// 序列化的可传输秘密密钥（TSK）字节
    secret_bytes: Vec<u8>,
    /// 序列化的公开证书字节（TPK）
    public_bytes: Vec<u8>,
    /// 在内存中也保留 Cert 以便操作（不会序列化到磁盘）
    #[zeroize(skip)]
    cert: Cert,
}

impl SecureKey {
    /// 使用 sequoia 生成一个包含 user_id 的密钥对（OpenPGP Cert），并保存序列化表示
    pub fn generate(user_id: &str) -> Result<Self, anyhow::Error> {
        let mut builder = CertBuilder::new();
        builder = builder.add_userid(user_id);

        // generate() 返回 (Cert, KeyPair)；Cert 包含公开信息和秘密密钥包
        let (cert, _key) = builder.generate()?;

        let mut secret_out = Vec::new();
        cert.as_tsk().serialize_into(&mut secret_out)?;

        let mut public_out = Vec::new();
        cert.serialize_into(&mut public_out)?;

        Ok(Self { secret_bytes: secret_out, public_bytes: public_out, cert })
    }

    /// 获取公开证书的序列化字节（可用于生成标准 OpenPGP 公钥证书）
    pub fn public_cert_bytes(&self) -> Vec<u8> {
        self.public_bytes.clone()
    }

    /// 获取秘密密钥的序列化字节（未加密）
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_bytes.clone()
    }

    /// 从私钥和密码派生加密密钥（PBKDF2-SHA256）
    pub fn derive_encryption_key(password: &str, salt: &[u8]) -> Result<[u8; 32], anyhow::Error> {
        use hmac::Hmac;
        use pbkdf2::pbkdf2;
        use sha2::Sha256;

        let mut key = [0u8; 32];
        let _ = pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            salt,
            100_000, // 迭代次数
            &mut key,
        );

        Ok(key)
    }
}