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
        // 强制使用 NIST P-256 (secp256r1) 作为主密钥算法，以避免在 Windows CNG 后端上
        // 对某些默认算法（如 Ed25519）出现序列化问题。
        builder = builder.set_cipher_suite(openpgp::cert::CipherSuite::P256);

        // generate() 返回 (Cert, KeyPair)；Cert 包含公开信息和秘密密钥包
        let gen_res = builder.generate();
        let (cert, _key) = match gen_res {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("CertBuilder::generate() error: {:?}", e);
                let mut src = e.source();
                while let Some(s) = src {
                    eprintln!("Caused by: {:?}", s);
                    src = s.source();
                }
                return Err(anyhow::anyhow!("CertBuilder::generate() failed: {:?}", e));
            }
        };

        // 输出证书包含的密钥计数（仅在 debug 构建时打印）
        if cfg!(debug_assertions) {
            let key_count = cert.keys().count();
            eprintln!("cert.keys() count: {}", key_count);

            // 打印完整 Cert 的调试信息，便于诊断序列化问题
            eprintln!("cert debug: {:#?}", cert);
        }

        // 使用 ASCII 装甲导出（保证 GnuPG 可导入）
        // 公钥（TPK）装甲
        let public_out = match cert.armored().to_vec() {
            Ok(v) => v,
            Err(e) => {
                if cfg!(debug_assertions) {
                    eprintln!("armored public cert failed: {:?}", e);
                    let mut src = e.source();
                    while let Some(s) = src {
                        eprintln!("Caused by: {:?}", s);
                        src = s.source();
                    }
                }
                return Err(anyhow::anyhow!("armored public cert failed: {:?}", e));
            }
        };

        // 私钥（TSK）装甲（包含秘密密钥包）
        let secret_out = match cert.as_tsk().armored().to_vec() {
            Ok(v) => v,
            Err(e) => {
                if cfg!(debug_assertions) {
                    eprintln!("armored secret tsk failed: {:?}", e);
                    let mut src = e.source();
                    while let Some(s) = src {
                        eprintln!("Caused by: {:?}", s);
                        src = s.source();
                    }
                }
                return Err(anyhow::anyhow!("armored secret tsk failed: {:?}", e));
            }
        };

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