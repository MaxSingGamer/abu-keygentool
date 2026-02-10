pub mod encryption;

use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, KeyPair},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 安全密钥容器 - 自动清零内存
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    /// PKCS#8 私钥字节，可安全清零
    pkcs8: Vec<u8>,
    public_key: Vec<u8>,
}

impl SecureKey {
    /// 生成新的 ECC P-256 密钥对并返回可序列化的私钥 (PKCS#8)
    pub fn generate() -> Result<Self, anyhow::Error> {
        let rng = SystemRandom::new();

        // 生成 PKCS#8 私钥
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| anyhow::anyhow!("Failed to generate PKCS8 private key: {:?}", e))?;

        // 从 PKCS#8 创建 KeyPair，从中获取公钥
        let rng_ref = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref(), &rng_ref)
            .map_err(|e| anyhow::anyhow!("Failed to parse generated PKCS8: {:?}", e))?;

        let public_key = key_pair.public_key().as_ref().to_vec();

        Ok(Self {
            pkcs8: pkcs8_bytes.as_ref().to_vec(),
            public_key,
        })
    }

    /// 获取公钥（用于导出）
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// 导出 PKCS#8 私钥字节
    #[allow(dead_code)]
    pub fn export_pkcs8(&self) -> Vec<u8> {
        self.pkcs8.clone()
    }

    /// 从私钥和密码派生加密密钥
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