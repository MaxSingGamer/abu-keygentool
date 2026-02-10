use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub struct Config {
    pub default_key_type: String,
    pub default_curve: String,
    pub encryption_iterations: u32,
    pub key_expiry_days: u32,
    pub abu_contact: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_key_type: "ECC".to_string(),
            default_curve: "P-256".to_string(),
            encryption_iterations: 100_000,
            key_expiry_days: 365 * 5, // 5年有效期
            abu_contact: "contact@abu.mc".to_string(),
        }
    }
}

#[allow(dead_code)]
impl Config {
    pub fn load() -> Self {
        // 简化版本 - 实际应从文件加载
        Self::default()
    }
    
    pub fn save(&self) -> Result<(), anyhow::Error> {
        // 保存配置到文件
        Ok(())
    }
}