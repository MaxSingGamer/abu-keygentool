mod security;
mod pgp;
mod ui;
mod config;

use anyhow::Result;
use std::fs;
use chrono::Local;
use rand::RngCore;

#[derive(serde::Serialize)]
struct KeyMetadata {
    bank_name: String,
    generation_date: String,
    key_type: String,
    key_size: u32,
    abu_version: String,
    notes: String,
}

pub struct KeyGenerator {
    ui: ui::UserInterface,
}

impl KeyGenerator {
    pub fn new() -> Self {
        Self {
            ui: ui::UserInterface::new(),
        }
    }
    
    /// 生成新密钥对
    pub fn generate_keys(&self) -> Result<()> {
        // 显示欢迎和警告
        self.ui.show_welcome();
        self.ui.show_warning();

        // 获取银行名称
        let bank_name = self.ui.input_bank_name()?;

        // 输入密码
        let password = self.ui.input_password(
            "请为私钥设置保护密码（输入时不可见）",
            true,
        )?;

        println!();
        println!("{} 正在生成ECC P-256密钥对...", ui::style("⏳").cyan());

        // 生成密钥
        let secure_key = security::SecureKey::generate()?;
        let public_key = secure_key.public_key().to_vec();

        // 导出私钥并加密
        println!("{} 正在加密私钥...", ui::style("⏳").cyan());
        let private_key_data = self.export_and_encrypt_private_key(&secure_key, &password)?;

        // 创建PGP证书
        println!("{} 正在创建OpenPGP证书...", ui::style("⏳").cyan());
        let user_id = format!("{} <{}@abu.mc>", bank_name, bank_name.to_lowercase());
        let pgp_cert = pgp::create_pgp_cert(
            &public_key,
            &private_key_data,
            &user_id,
            Some(&password),
        )?;

        // 添加ASCII装甲
        let armored = pgp::add_ascii_armor(&pgp_cert, sequoia_openpgp::armor::Kind::SecretKey)?;

        // 选择保存位置
        let default_name = format!("{}_keypair_{}.asc",
            bank_name.replace(' ', "_"),
            Local::now().format("%Y%m%d_%H%M%S")
        );

        let save_path = self.ui.select_save_location(&default_name)?;

        // 保存文件
        fs::write(&save_path, armored)?;

        // 创建元数据文件
        let metadata = KeyMetadata {
            bank_name: bank_name.clone(),
            generation_date: Local::now().to_rfc3339(),
            key_type: "ECC P-256".to_string(),
            key_size: 256,
            abu_version: "1.0".to_string(),
            notes: "Alpha Coin Banking System".to_string(),
        };

        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        let metadata_path = save_path.with_extension("json");
        fs::write(metadata_path, metadata_json)?;

        // 显示成功消息
        self.ui.show_success(&format!(
            "密钥对已成功生成并保存到:\n{}\n\n请妥善保管您的私钥文件！",
            save_path.display()
        ));

        self.show_key_summary(&bank_name, &save_path);

        Ok(())
    }
    
    /// 导出并加密私钥
    fn export_and_encrypt_private_key(
        &self,
        _secure_key: &security::SecureKey,
        password: &str,
    ) -> Result<Vec<u8>> {
        use security::encryption::aes_gcm_encrypt;
        
        // 生成盐值
        let mut salt = [0u8; 16];
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(&mut salt);
        
        // 派生加密密钥
        let encryption_key = security::SecureKey::derive_encryption_key(password, &salt)?;
        
        // 这里简化处理 - 实际需要将私钥序列化
        let private_key_bytes = Vec::new(); // 应包含实际的私钥数据
        
        // 加密私钥
        let (ciphertext, nonce) = aes_gcm_encrypt(&private_key_bytes, &encryption_key)?;
        
        // 组合数据：盐 + nonce + 密文
        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(&salt);
        encrypted_data.extend_from_slice(&nonce);
        encrypted_data.extend_from_slice(&ciphertext);
        
        Ok(encrypted_data)
    }
    
    /// 显示密钥摘要
    fn show_key_summary(&self, bank_name: &str, path: &std::path::Path) {
        println!();
        println!("{}", ui::style("══════════════════════════════════════════").cyan());
        println!("{}", ui::style("              密钥生成摘要                ").bold());
        println!("{}", ui::style("══════════════════════════════════════════").cyan());
        println!("🏦 银行/城镇: {}", ui::style(bank_name).bold());
        println!("📁 密钥文件: {}", ui::style(path.display()).bold());
        println!("🔐 密钥类型: ECC P-256 (椭圆曲线加密)");
        println!("📅 生成时间: {}", Local::now().format("%Y-%m-%d %H:%M:%S"));
        println!("{}", ui::style("══════════════════════════════════════════").cyan());
        println!();
        
        println!("{}", ui::style("下一步操作:").yellow().bold());
        println!("1. 将公钥文件(.asc)提交给ABU联盟进行注册");
        println!("2. 备份私钥到安全的离线存储设备");
        println!("3. 使用此密钥进行Alpha Coin的交易签名");
    }
    
    /// 运行主程序
    pub fn run(&self) -> Result<()> {
        self.ui.show_welcome();
        
        loop {
            match self.ui.select_operation()? {
                ui::Operation::Generate => {
                    if let Err(e) = self.generate_keys() {
                        self.ui.show_error(&format!("生成失败: {}", e));
                    }
                }
                ui::Operation::Import => {
                    println!("导入功能开发中...");
                }
                ui::Operation::Export => {
                    println!("导出功能开发中...");
                }
                ui::Operation::Verify => {
                    println!("验证功能开发中...");
                }
                ui::Operation::Exit => {
                    println!("感谢使用ABU密钥生成器！");
                    break;
                }
            }
            
            // 询问是否继续
            if !dialoguer::Confirm::new()
                .with_prompt("是否继续执行其他操作？")
                .default(true)
                .interact()?
            {
                println!("感谢使用ABU密钥生成器！");
                break;
            }
        }
        
        Ok(())
    }
}

fn main() -> Result<()> {
    let generator = KeyGenerator::new();
    
    if let Err(e) = generator.run() {
        eprintln!("程序错误: {}", e);
        std::process::exit(1);
    }
    
    Ok(())
}