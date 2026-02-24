mod security;
mod pgp;
mod ui;
mod encryption;

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

    /// 解密并导出私钥文件的交互流程
    fn decrypt_private_key_flow(&self) -> Result<()> {
        // 选择要解密的加密私钥文件
        let path = self.ui.select_open_location()?;
        let data = std::fs::read(&path)?;

        if data.len() < 28 {
            return Err(anyhow::anyhow!("文件太短，无法包含 salt/nonce/密文"));
        }

        // 读取 salt(16) + nonce(12) + ciphertext
        let salt = &data[0..16];
        let nonce = &data[16..28];
        let ciphertext = &data[28..];

        // 输入密码
        let password = self.ui.input_password("请输入用于解密私钥的密码（输入时不可见）", false)?;

        // 派生密钥并解密
        let key = security::SecureKey::derive_encryption_key(&password, salt)?;
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce);

        let plaintext = encryption::aes_gcm_decrypt(ciphertext, &key, &nonce_arr)?;

        // 警告并询问是否保存明文私钥
        println!("警告：即将导出私钥原文，可能导致密钥泄露！");
        if dialoguer::Confirm::new()
            .with_prompt("确认导出私钥原文并以 ASCII 装甲保存？")
            .default(false)
            .interact()? {
            let default_name = format!("decrypted_private_{}.asc", Local::now().format("%Y%m%d_%H%M%S"));
            let save_path = self.ui.select_save_location(&default_name)?;
            let armored = pgp::add_ascii_armor(&plaintext, sequoia_openpgp::armor::Kind::SecretKey)?;
            std::fs::write(save_path, armored)?;
            println!("私钥已保存（明文装甲）。请尽快安全删除该文件。");
        }

        Ok(())
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

        // 生成密钥（使用 OpenPGP user id 使得证书与私钥匹配）
        // 让用户输入邮箱，以便构建标准的 User ID
        let email = self.ui.input_email()?;
        let user_id = format!("{} <{}>", bank_name, email);
        let secure_key = match security::SecureKey::generate(&user_id) {
            Ok(k) => k,
            Err(e) => {
                // 打印错误链以便诊断
                eprintln!("SecureKey::generate() failed: {:?}", e);
                let mut src = e.source();
                while let Some(s) = src {
                    eprintln!("Caused by: {:?}", s);
                    src = s.source();
                }
                return Err(e);
            }
        };
        let public_bytes = secure_key.public_cert_bytes();

        // 导出私钥并加密
        println!("{} 正在加密私钥...", ui::style("⏳").cyan());
        let private_key_data = self.export_and_encrypt_private_key(&secure_key, &password)?;

        // 创建并保存公钥（ASCII 装甲），以及保存加密私钥为单独二进制文件
        println!("{} 正在创建并导出公钥与加密私钥...", ui::style("⏳").cyan());

        // 公钥已由 SecureKey 以 ASCII 装甲生成，直接使用 bytes
        // public_bytes may already be an ASCII-armored UTF-8 buffer; try to convert safely
        let armored_public = match String::from_utf8(public_bytes.clone()) {
            Ok(s) => s,
            Err(_) => pgp::add_ascii_armor(&public_bytes, sequoia_openpgp::armor::Kind::PublicKey)?,
        };

        // 选择保存公钥位置
        let default_pub_name = format!("{}_public_{}.asc",
            bank_name.replace(' ', "_"),
            Local::now().format("%Y%m%d_%H%M%S")
        );
        let pub_save_path = self.ui.select_save_location(&default_pub_name)?;

        // 保存公钥文件
        fs::write(&pub_save_path, armored_public)?;

        // 私钥文件名和路径（与公钥所在目录相同）
        let private_name = format!("{}_private_{}.bin",
            bank_name.replace(' ', "_"),
            Local::now().format("%Y%m%d_%H%M%S")
        );
        let private_path = pub_save_path.parent().unwrap_or(std::path::Path::new("")).join(private_name);

        // 保存加密私钥（二进制包含 salt||nonce||ciphertext）
        fs::write(&private_path, &private_key_data)?;

        // 注意：不在生成完成时导出可直接被 GnuPG 导入的私钥。
        // 私钥的明文导出改为通过主菜单的“解密并导出”功能进行，
        // 以保证用户在导出前主动解密并确认风险。

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
        let metadata_path = pub_save_path.with_extension("json");
        fs::write(metadata_path, metadata_json)?;

        // 显示成功消息（列出公钥与私钥保存位置）
        self.ui.show_success(&format!(
            "公钥已保存到: {}\n私钥（已加密）已保存到: {}\n\n请妥善保管您的私钥文件！",
            pub_save_path.display(),
            private_path.display(),
        ));

        self.show_key_summary(&bank_name, &pub_save_path);

        Ok(())
    }
    
    /// 导出并加密私钥
    fn export_and_encrypt_private_key(
        &self,
        secure_key: &security::SecureKey,
        password: &str,
    ) -> Result<Vec<u8>> {
        use encryption::aes_gcm_encrypt;

        // 生成盐值
        let mut salt = [0u8; 16];
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(&mut salt);

        // 派生加密密钥
        let encryption_key = security::SecureKey::derive_encryption_key(password, &salt)?;

        // 导出私钥为 OpenPGP secret bytes（未加密）
        let private_key_bytes = secure_key.secret_key_bytes();

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
        println!("🏦 银行/玩家名: {}", ui::style(bank_name).bold());
        println!("📁 密钥文件: {}", ui::style(path.display()).bold());
        println!("🔐 密钥类型: ECC P-256 (椭圆曲线加密)");
        println!("📅 生成时间: {}", Local::now().format("%Y-%m-%d %H:%M:%S"));
        println!("{}", ui::style("══════════════════════════════════════════").cyan());
        println!();
        
        println!("{}", ui::style("请自行操作下一步:").yellow().bold());
        println!("1. 将公钥文件(.asc)提交给ABU/银行进行注册");
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
                ui::Operation::Decrypt => {
                    if let Err(e) = self.decrypt_private_key_flow() {
                        self.ui.show_error(&format!("解密失败: {}", e));
                    }
                }
                ui::Operation::Exit => {
                    println!("感谢使用ABU密钥生成器");
                    break;
                }
            }
            
            // 询问是否继续
            if !dialoguer::Confirm::new()
                .with_prompt("是否继续执行其他操作？")
                .default(true)
                .interact()?
            {
                println!("感谢使用ABU密钥生成器");
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