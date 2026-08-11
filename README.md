# ModelLock —— 更强 VTS 模型锁（完整实现）

激活码授权 + 一人一码一设备 + 密码学绑定的加密包 + Dokan 按需解密挂载。

## 桌面 Demo（两个带 UI 的软件）

| 软件 | 位置 | 技术 | 功能 |
|---|---|---|---|
| 买家端 `modelock-client-ui` | `client-ui/` | Rust + egui | 我的模型 / 添加 .vkit+激活码 / 一键挂载 / 信任作者 / 设置（卸载不杀 VTS） |
| 画师端 `ModelLockArtist` | `artist-ui/` | Python + PySide6 | 作者密钥 / 发码 / 打包 / 台账 / 日志 |

Windows 构建（见 `packaging/build_windows.ps1`）：

```powershell
# 买家端
cd client-ui; cargo build --release
# 画师端
python -m pip install PySide6 cryptography pyinstaller
python -m PyInstaller --noconfirm --onefile --windowed --name ModelLockArtist --paths . artist-ui/main.py
```

安装包：用 Inno Setup 编译 `packaging/ModelLockClient.iss` / `packaging/ModelLockArtist.iss`（绿色版直接取 exe 即可）。

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
│ 授权服务器   │ ◀────────────────  │ (stdlib+SQLite)│
└─────────────┘                   └──────────────┘
```

## 目录

| 目录 | 内容 | 平台 |
|---|---|---|
| `packager/` | 画师端打包工具（Python，`.vkit` 加密包） | 任意（Linux 已测） |
| `server/` | 授权服务器（Python 标准库 + SQLite + HMAC 令牌） | 任意（Linux 已测） |
| `client/` | 买家客户端（Rust：CNG 密钥、Dokan 挂载、VTS 拉起/授权） | Windows 10/11 x64 |
| `docs/vkit-format.md` | `.vkit` 二进制格式规范 | — |
| `docs/windows-test-guide.md` | Windows 本机测试指南 | — |
| `model-lock-security-design.md` | 完整方案设计文档 | — |

Windows 客户端实测步骤见 [docs/windows-test-guide.md](docs/windows-test-guide.md)。

## 快速开始（Linux 上可完整验证的部分）

依赖：Python 3.10+，`pip install cryptography`（测试不需要额外包）。

```bash
# 1. 打包工具 + 服务器单元测试
python3 -m unittest packager.tests.test_vkit server.tests.test_server -v

# 2. 端到端：发码 → 买家激活 → 打包 → 解密还原
python3 tests/e2e.py
```

## 离线验证模式（推荐，无需服务器）

1. 画师生成作者密钥并导出公钥文件：
   ```bash
   python3 -m packager.cli gen-key --output author.pem
   python3 -m packager.cli export-author-key --key author.pem --output author.spki
   ```
2. 买家运行客户端 `init` 导出 `.vreq` 发给画师；
3. 画师为该买家发激活码（本地台账，绑定买家 key_id）：
   ```bash
   python3 -m packager.cli gen-code --model-id 小樱 --key-id <买家key_id> --note 阿花
   ```
4. 画师打包（许可声明随包签名）：
   ```bash
   python3 -m packager.cli pack --model-dir 模型目录 --vreq 买家.vreq \
     --output 小樱-阿花.vkit --author-key author.pem --code ML-XXXX --expires 2027-12-31
   ```
5. 买家首次使用：`trust-author --file author.spki`，然后 `mount --vkit 小樱-阿花.vkit --code ML-XXXX`；
   之后同一模型再次 mount 不再需要输码（本地已缓存许可）。

> 全程无服务器参与：作者签名 + 买家公钥封装 CEK + 激活码哈希绑定 key_id，
> “一人一码”在密码学层面成立。原 server/ 目录保留为可选的在线模式。

## 端到端流程

1. 买家运行客户端 `init --vreq-out VVON-授权请求.vreq`，导出公钥请求文件；
2. 画师运行 `python3 -m packager.cli pack --model-dir 模型目录 --vreq 买家.vreq --output 模型-买家.vkit --author-key author.pem`；
3. 服务器管理员生成激活码：`POST /api/admin/codes`（见 `server/server.py` 或测试）；
4. 买家输入激活码：`modelock-client activate --server http://127.0.0.1:8787 --code ML-XXXX`；
5. 买家加载：`modelock-client mount --vkit 模型-买家.vkit`，客户端挂载虚拟盘、拉起 VTS、只授权这个 VTS 实例读取；卸载即杀 VTS。

## Windows 客户端编译与运行

```powershell
# 前提：Rust MSVC 工具链、Dokan SDK（https://dokan-dev.github.io）
cd client
cargo build --release

# 首次使用：生成设备密钥（CNG/KSP，私钥不可导出）并导出请求文件
target\release\modelock-client.exe init --vreq-out 授权请求.vreq

# 激活（把请求文件发给画师，等 .vkit 回来）
target\release\modelock-client.exe activate --server http://你的服务器:8787 --code ML-XXXX

# 挂载并启动 VTS
target\release\modelock-client.exe mount --vkit 模型-买家.vkit
```

> VTS 只通过 Steam 分发。客户端**强制走 Steam 启动**：调用 `steam.exe -applaunch 1325860`，
> 然后轮询监听新出现的 `VTube Studio.exe` 进程，仅当它的父进程是 `steam.exe` 时才授权挂载
> （手动双击或 `-nosteam` 直启的实例不会被授权）。VNet 等 Steam 功能因此保持可用。
> 开发调试可用 `--launch-mode nosteam` 直启。

## 安全边界（务必阅读）

- 本实现的目标是抬高门槛：防随手转发（`.vkit` 绑定买家公钥，转发无效）、防扒包工具（读取预算 + 目录枚举拒绝）、防共享激活码（服务端绑定设备）。
- 无法防住“完全控制本机”的专业攻击者：模型渲染时内存/显存中必然存在明文。
- 客户端（`client/`）需在 Windows 上编译与实测；本仓库在 Linux 环境完成了打包器、服务器和端到端流程的验证。
