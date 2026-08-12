# 星零集模型锁（ModelLock）

VTube Studio 模型保护方案：激活码授权 · 一人一码一设备 · 密码学绑定的加密包（`.vkit`）· Dokan 按需解密挂载。

## 📥 下载安装

两个桌面应用（**仅 Windows**，Windows 10/11 64 位）请在 [Releases](../../releases) 页面下载：

| 安装包 | 应用 | 用途 |
|---|---|---|
| `ModelLockClient-Setup.exe` | 星零集模型锁（买家端） | 导入 `.vkit`、输入激活码、挂载给 VTube Studio |
| `ModelLockArtist-Setup.exe` | 星零集模型锁-画师端 | 生成作者密钥、发激活码、打包模型、管理台账 |

> 安装包已内置 Dokan 文件系统运行时（静默安装），**无需手动安装任何运行库**。
> 过期校验使用联网时间（HTTPS 获取，不信任系统时钟），**使用前请确保电脑能联网**。

## 系统要求（仅 Windows）

- **Windows 10 / 11 64 位**（不支持 32 位、macOS、Linux 客户端）
- **Steam**：挂载时需保持运行
- **VTube Studio**：通过 Steam 安装（Steam 内免费下载），挂载时会由客户端自动拉起
- **网络连接**：授权与过期校验依赖联网时间

## 使用注意事项

**买家端**

- 挂载前需先**关闭**正在运行的 VTube Studio，并确认 **Steam 已打开**（客户端会检测并提示，不满足不会继续挂载）。
- 只授权本次由 Steam 启动的 VTube Studio 实例访问模型；手动双击或绕过 Steam 启动的实例不会被授权。
- 激活码**一人一码、绑定本机设备**：同一激活码换机器无效；`.vkit` 已绑定买家设备公钥，转发给他人也无法使用。
- 模型有效期支持「永久」或「N 年 M 月」（默认 10 年），到期后需联系画师重新打包续期。
- 卸载时默认不关闭 VTube Studio（设置里可勾选“卸载时同时关闭”）。
- 程序为单实例：重复打开会提示并退出。

**画师端**

- 作者私钥（`author.pem`）**切勿发给买家**；买家只需要公钥文件 `author.spki`。
- 激活码台账保存在本地 SQLite（`license_records.db`），支持按时间范围导出 CSV。
- 打包时填写的期限即为许可期限，过期校验在买家端通过联网时间执行。

**安全边界（务必阅读）**

- 本方案的目标是抬高门槛：防随手转发（`.vkit` 绑定买家公钥）、防扒包工具（读取预算 + 目录枚举拒绝）、防共享激活码（设备绑定）。
- 无法防住“完全控制本机”的专业攻击者：模型渲染时内存/显存中必然存在明文。

## 快速开始

### 买家

1. 安装并打开买家端，在「信任作者」页导入画师发来的 `author.spki`；
2. 点击「导出授权请求」，得到 `.vreq` 文件发给画师；
3. 收到画师返回的 `.vkit` 和激活码后，在「我的模型」页添加 `.vkit`，输入激活码并挂载；
4. 挂载成功后 VTube Studio 自动通过 Steam 启动，模型出现在其 Live2DModels 列表中。

### 画师

1. 「作者密钥」页生成新密钥（或加载已有 `author.pem`），导出 `author.spki` 发给买家；
2. 收到买家 `.vreq` 后，在「授权码」页读取其中的 key_id 并生成激活码（可选「永久」或 N 年 M 月期限）；
3. 「打包模型」页选择模型目录、买家 `.vreq`、激活码与期限，输出 `.vkit`；
4. 把 `.vkit` 和激活码发给买家；「台账」页可随时导出发码记录。

## 架构

```
┌────────────┐   .vreq(买家公钥)   ┌──────────────┐
│ 买家客户端  │ ──────────────────▶ │ 画师端打包器  │
│ (Windows)  │ ◀────────────────── │ (Python)     │
└─────┬──────┘      .vkit          └──────┬───────┘
      │                                   │ 模型目录
      │ 激活码/设备绑定/令牌               ▼
      ▼                            ┌──────────────┐
┌─────────────┐   /api/*          │ 授权服务器     │
│ 授权服务器   │ ◀────────────────  │ (可选,在线模式)│
└─────────────┘                   └──────────────┘
```

主要场景为完全离线的「作者签名 + 买家公钥封装 CEK + 激活码哈希绑定 key_id」，一人一码在密码学层面成立；`server/` 保留为可选的在线激活模式。

## 目录

| 目录 | 内容 | 平台 |
|---|---|---|
| `packager/` | 画师端打包工具（Python，`.vkit` 加密包） | 任意（Linux 可测） |
| `server/` | 授权服务器（可选在线模式，Python 标准库 + SQLite） | 任意 |
| `client/` | 买家客户端核心（Rust：CNG 密钥、Dokan 挂载、VTS 拉起/授权） | **仅 Windows 10/11 x64** |
| `client-ui/` | 买家端 GUI（Rust + egui） | **仅 Windows 10/11 x64** |
| `artist-ui/` | 画师端 GUI（Python + PySide6） | Windows（打包工具本身任意平台） |
| `docs/` | `.vkit` 格式规范、Windows 测试指南 | — |

## 开发构建

```powershell
# 买家端（需要 Rust MSVC 工具链；图标/Logo 经 build.rs 内嵌）
cd client-ui
cargo build --release

# 画师端（需要 Python 3.10+、PySide6、cryptography、pyinstaller）
cd ..
python -m pip install PySide6 cryptography pyinstaller pillow
python -m PyInstaller --noconfirm --clean --onefile --windowed --name ModelLockArtist `
  --paths . --add-data "docs/logo.png;docs" --icon "packaging/icon.ico" artist-ui/main.py
```

安装包：用 Inno Setup 编译 `packaging/ModelLockClient.iss` / `packaging/ModelLockArtist.iss`（买家端安装包会内置 Dokan v2 运行时）。

测试（打包器 + 服务器单元测试与端到端流程，Linux 亦可跑）：

```bash
python3 -m unittest packager.tests.test_vkit server.tests.test_server -v
python3 tests/e2e.py
```

## 致谢与许可

- 本项目参考了 [BarryWangQwQ/ProjectVFS](https://github.com/BarryWangQwQ/ProjectVFS)（基于 Windows Dokan 的虚拟文件系统）的设计思路，特此致谢。
- 软件源码以 [MIT 许可证](LICENSE) 发布，Copyright (c) 2026 古守の香香G（bilibili@古守の香香G）。
- 授权服务与模型内容（激活码、加密 `.vkit` 包）为作者独立提供的服务，适用「关于」对话框中的使用条款：激活码与设备绑定，禁止转售/共享；禁止逆向、破解或绕过授权机制；禁止将解密后的模型重新打包、传播或商用；禁止转售本软件；不得用于任何违法违规用途。
