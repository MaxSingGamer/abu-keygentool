pub mod encryption;

use ring::{
    agreement::{EphemeralPrivateKey, ECDH_P256},
    rand::SystemRandom,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 安全密钥容器 - 自动清零内存
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    #[zeroize(skip)]  // ring的密钥有自己的安全机制
    private_key: EphemeralPrivateKey,
    public_key: Vec<u8>,
}

impl SecureKey {
    /// 生成新的ECC P-256密钥对
    pub fn generate() -> Result<Self, anyhow::Error> {
        let rng = SystemRandom::new();
        
        // 生成私钥
        let private_key = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
            .map_err(|e| anyhow::anyhow!("Failed to generate private key: {:?}", e))?;
        
        // 导出公钥
        let public_key = private_key.compute_public_key()
            .map_err(|e| anyhow::anyhow!("Failed to compute public key: {:?}", e))?
            .as_ref()
            .to_vec();
        
        Ok(Self {
            private_key,
            public_key,
        })
    }
    
    /// 获取公钥（用于导出）
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    
    /// 获取私钥引用（谨慎使用）
    #[allow(dead_code)]
    pub fn private_key(&self) -> &EphemeralPrivateKey {
        &self.private_key
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
            100_000,  // 迭代次数
            &mut key
        );
        
        Ok(key)
    }
}