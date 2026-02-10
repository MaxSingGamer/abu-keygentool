use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
// zeroize removed (no local SecureBuffer present)

/// 使用AES-GCM加密数据
pub fn aes_gcm_encrypt(
    plaintext: &[u8],
    key: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 12]), anyhow::Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    
    // 生成随机nonce
    let mut nonce_bytes = [0u8; 12];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
    
    Ok((ciphertext, nonce_bytes))
}

/// 使用AES-GCM解密数据
#[allow(dead_code)]
pub fn aes_gcm_decrypt(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, anyhow::Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
    
    Ok(plaintext)
}

// SecureBuffer removed (unused). Add back if secure buffer semantics are needed.