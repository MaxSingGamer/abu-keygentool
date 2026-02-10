# ABU Keygen Tool

Alpha Bank Union (ABU) — ECC 密钥生成器，用于生成 OpenPGP 兼容的密钥对并导出公钥/私钥。

功能概要
- 使用 sequoia-openpgp 生成匹配的 OpenPGP 密钥对（P-256）
- 导出标准 OpenPGP 公钥（ASCII 装甲 `.asc`）用于转发
- 将私钥序列化并使用密码派生密钥 (PBKDF2-SHA256) + AES-GCM 加密，保存为二进制文件
- 可选导出私钥原文（带明显不安全警告）
- 支持从加密私钥文件解密并导出私钥（需密码）

快速开始

1. 构建（需要 Rust 工具链）

```bash
cargo build --release
```

2. 运行

```bash
cargo run --release --bin abu-keygentool
```

3. 生成后：
- 公钥将以 `.asc`（OpenPGP 公钥）保存，适合转发给对方；
- 私钥将作为加密二进制保存（格式：salt(16) || nonce(12) || ciphertext）；
- 如需恢复私钥，请使用程序的 “解密/导出私钥（需密码）” 菜单项。

安全说明
- 私钥请务必离线备份并妥善保管；导出明文私钥极不安全，仅在非常受控的环境下短时使用。

许可证
- 本项目采用 MIT 许可证，详见 `LICENSE`。

作者
- Max Shin <xhzmax@outlook.com>
