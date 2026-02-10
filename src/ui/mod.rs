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
        println!("{}", style("║      阿尔法银行联盟 (ABU)              ║").cyan());
        println!("{}", style("║      Alpha Coin 密钥生成器              ║").cyan());
        println!("{}", style("╚══════════════════════════════════════════╝").cyan());
        println!();
        println!("欢迎使用 Alpha Coin 密钥生成工具");
        println!("此工具将为您的联邦储蓄与信贷银行(FSCB)生成安全的ECC密钥对");
        println!();
    }
    
    /// 选择主操作
    pub fn select_operation(&self) -> Result<Operation> {
        let items = vec![
            "生成新的密钥对",
            "导入现有密钥",
            "导出公钥",
            "验证密钥",
            "退出程序",
        ];
        
        let selection = Select::with_theme(&self.theme)
            .with_prompt("请选择要执行的操作")
            .items(&items)
            .default(0)
            .interact()?;
        
        match selection {
            0 => Ok(Operation::Generate),
            1 => Ok(Operation::Import),
            2 => Ok(Operation::Export),
            3 => Ok(Operation::Verify),
            4 => Ok(Operation::Exit),
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
            .with_prompt("请输入您的银行/城镇名称")
            .default("联邦储蓄与信贷银行".to_string())
            .interact()?;
        
        Ok(name)
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
        println!("{}", style("4. 私钥丢失将导致资产永久无法访问").yellow());
        
        Confirm::with_theme(&self.theme)
            .with_prompt("我已阅读并理解上述警告")
            .default(true)
            .interact()
            .ok();
    }
}

pub enum Operation {
    Generate,
    Import,
    Export,
    Verify,
    Exit,
}