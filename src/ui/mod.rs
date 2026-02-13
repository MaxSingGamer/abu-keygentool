use dialoguer::{
    theme::ColorfulTheme,
    Select, Password, Confirm, Input
};
pub use console::style;
use native_dialog::FileDialog;
use std::path::PathBuf;
use anyhow::Result;

pub struct UserInterface {
    theme: ColorfulTheme,
}

impl UserInterface {
    pub fn new() -> Self {
        Self {
            theme: ColorfulTheme::default(),
        }
    }
    
    /// 显示欢迎界面
    pub fn show_welcome(&self) {
        println!();
        println!("{}", style("╔══════════════════════════════════════════╗").cyan());
        println!("{}", style("║           ABU - Alpha Bank Union         ║").cyan());
        println!("{}", style("║              通用密钥生成器              ║").cyan());
        println!("{}", style("║   ©2026 Max Shin - All Rights Reserved.  ║").cyan());
        println!("{}", style("╚══════════════════════════════════════════╝").cyan());
        println!();
        println!("欢迎使用 Alpha Bank Union 通用密钥生成器");
        println!("此工具将为您生成安全的ECC密钥对");
        println!();
    }
    
    /// 选择主操作
    pub fn select_operation(&self) -> Result<Operation> {
        let items = vec![
            "生成新的密钥对",
            "解密/导出私钥（需密码）",
            "退出程序",
        ];
        
        let selection = Select::with_theme(&self.theme)
            .with_prompt("请选择要执行的操作")
            .items(&items)
            .default(0)
            .interact()?;
        
        match selection {
            0 => Ok(Operation::Generate),
            1 => Ok(Operation::Decrypt),
            2 => Ok(Operation::Exit),
            _ => Ok(Operation::Exit),
        }
    }
    
    /// 输入密码
    pub fn input_password(&self, prompt: &str, confirmation: bool) -> Result<String> {
        let password = Password::with_theme(&self.theme)
            .with_prompt(prompt)
            .interact()?;
        
        if confirmation {
            let confirm = Password::with_theme(&self.theme)
                .with_prompt("请再次确认密码")
                .interact()?;
            
            if password != confirm {
                return Err(anyhow::anyhow!("两次输入的密码不一致"));
            }
        }
        
        Ok(password)
    }
    
    /// 输入银行/城镇名称
    pub fn input_bank_name(&self) -> Result<String> {
        let name: String = Input::with_theme(&self.theme)
            .with_prompt("请输入您的银行/玩家名称")
            .default("Example".to_string())
            .interact()?;
        
        Ok(name)
    }

    /// 输入邮箱地址（用于 OpenPGP User ID）
    pub fn input_email(&self) -> Result<String> {
        let email: String = Input::with_theme(&self.theme)
            .with_prompt("请输入您的电子邮箱 (用于 User ID)")
            .validate_with(|input: &String| {
                if input.contains('@') && input.contains('.') {
                    Ok(())
                } else {
                    Err("请输入有效的邮箱地址")
                }
            })
            .interact()?;

        Ok(email)
    }
    
    /// 选择文件保存位置
    pub fn select_save_location(&self, default_name: &str) -> Result<PathBuf> {
        let path = FileDialog::new()
            .set_title("选择密钥保存位置")
            .set_filename(default_name)
            .show_save_single_file()
            .map_err(|e| anyhow::anyhow!("文件对话框错误: {:?}", e))?
            .ok_or_else(|| anyhow::anyhow!("用户取消了文件选择"))?;
        
        Ok(path)
    }

    /// 选择要打开的私钥文件（解密用）
    pub fn select_open_location(&self) -> Result<PathBuf> {
        let path = FileDialog::new()
            .set_title("选择要解密的私钥文件")
            .show_open_single_file()
            .map_err(|e| anyhow::anyhow!("文件对话框错误: {:?}", e))?
            .ok_or_else(|| anyhow::anyhow!("用户取消了文件选择"))?;

        Ok(path)
    }
    
    /// 显示成功消息
    pub fn show_success(&self, message: &str) {
        println!();
        println!("{} {}", style("✓").green().bold(), style(message).green());
        println!();
    }
    
    /// 显示错误消息
    pub fn show_error(&self, message: &str) {
        println!();
        println!("{} {}", style("✗").red().bold(), style(message).red());
        println!();
    }
    
    /// 显示重要警告
    pub fn show_warning(&self) {
        println!();
        println!("{}", style("重要安全警告:").yellow().bold());
        println!("{}", style("1. 请务必备份您的私钥文件").yellow());
        println!("{}", style("2. 不要将私钥分享给任何人").yellow());
        println!("{}", style("3. 设置强密码（建议12位以上）").yellow());
        println!("{}", style("4. 私钥丢失将导致您使用此密钥加密的资产永久无法访问").yellow());
        
        Confirm::with_theme(&self.theme)
            .with_prompt("我已阅读并理解上述警告")
            .default(true)
            .interact()
            .ok();
    }
}

pub enum Operation {
    Generate,
    Decrypt,
    Exit,
}