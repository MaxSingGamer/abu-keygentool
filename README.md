
# ABU Keygen Tool / ABU 密钥生成工具

English
-------
ABU Keygen Tool (Alpha Bank Union) is a small utility that generates ECC OpenPGP-compatible key pairs and exports public/private keys.

Main features:
- Generate matching OpenPGP key pairs (ECDSA P-256) using sequoia-openpgp.
- Export standard OpenPGP public key (ASCII-armored `.asc`) for sharing.
- Serialize secret key (TSK) and encrypt it with a password (PBKDF2-SHA256 + AES-GCM), saved as a binary blob.
- Optional plaintext secret export (INSECURE — use only in tightly controlled scenarios).
- Decrypt encrypted private-key files with password and optionally export plaintext.

Quick start:
```bash
cargo build --release
cargo run --release --bin abu-keygentool
```

Notes:
- After generation, public key is saved as a standard OpenPGP public certificate (`.asc`).
- Private key is saved as an encrypted binary: `salt(16) || nonce(12) || ciphertext`.
- To recover a private key, use the program's "Decrypt/Export Private Key (password required)" menu item.

Security:
- Always back up private keys offline and protect passwords. Exporting plaintext private keys is extremely unsafe and should only be done temporarily in controlled environments.

中文（Chinese）
----------------
本工具为 ABU（Alpha Bank Union）用以为玩家生成 OpenPGP 兼容的 ECC 密钥对，并支持公钥/私钥的导出与管理。

主要功能：
- 使用 `sequoia-openpgp` 生成匹配的 OpenPGP 密钥对（ECDSA P-256）。
- 导出标准 OpenPGP 公钥（ASCII 装甲 `.asc`），方便转发给他人。
- 将秘密密钥（TSK）序列化后使用密码进行加密（PBKDF2-SHA256 + AES-GCM），并保存为二进制文件。
- 可选导出私钥原文（不安全——仅限受控场景短时使用）。
- 支持对加密私钥文件进行解密并导出私钥（需密码）。

快速开始：
```bash
cargo build --release
cargo run --release --bin abu-keygentool
```

说明：
- 生成后，公钥将保存为标准 OpenPGP 公钥证书（`.asc`）。
- 私钥会以加密二进制形式保存，格式为：`salt(16) || nonce(12) || ciphertext`。
- 如需恢复私钥，请使用程序中的 “解密/导出私钥（需密码）” 选项。

安全提示：
- 请务必离线备份私钥并妥善保管密码。导出未加密的明文私钥风险极高，仅在受控环境下短时使用。

Usage Restriction / 使用约束
--------------------------------
This software was developed specifically for players of the GeoPolyCraft Minecraft server and is intended for that use only. Do not use it for other production systems without reviewing its security design and adapting it to your environment.

本软件专为 GeoPolyCraft（我的世界服务器）中的玩家设计，仅供该用途。请勿将其直接用于其他生产系统，除非已审查并按需增强安全性。

License / 许可
---------------
This project is licensed under the MIT License — see `LICENSE`.

本项目使用 MIT 许可证，详见 `LICENSE`。

Author / 作者
---------------
Max Shin <xhzmax@outlook.com>
