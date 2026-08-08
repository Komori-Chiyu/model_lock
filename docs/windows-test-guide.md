# Windows 本机测试指南（ModelLock 客户端）

> 说明：打包器（packager/）与服务器（server/）在 Linux 上已全部验证；
> 本节只针对需要 Windows 才能跑的买家客户端（Dokan 驱动、CNG 密钥、Steam 启动校验）。

## 0. 准备

1. Windows 10/11 x64 机器，Steam 已登录并安装 VTube Studio（免费，AppID 1325860）
2. Rust MSVC 工具链：<https://rustup.rs>
3. Dokan 运行时：<https://dokan-dev.github.io>（安装官方最新版，卸载旧版避免冲突）
4. 服务器依赖：`python3 -m pip install cryptography`

## 1. 编译客户端

```powershell
cd client
cargo build --release
# 产物：target\release\modelock-client.exe
```

## 2. 启动授权服务器（Linux 或 Windows 均可）

```bash
python3 server/server.py --db model_lock.db --port 8787
# 启动时打印 Admin Key，用于发码
```

生成激活码（管理员）：

```bash
curl -X POST http://127.0.0.1:8787/api/admin/codes \
  -H "Content-Type: application/json" \
  -d '{"admin_key":"<Admin Key>","model_id":"小樱","count":1,"max_devices":1}'
```

## 3. 画师打包

```bash
python3 -m packager.cli gen-key --output author.pem
# 等买家发来 .vreq 后：
python3 -m packager.cli pack \
  --model-dir "D:\模型\小樱" \
  --vreq "买家授权请求.vreq" \
  --output "小樱-买家.vkit" \
  --author-key author.pem
```

## 4. 买家侧（Windows）完整流程

```powershell
# 4.1 首次：生成设备密钥（CNG/KSP，私钥不可导出）并导出请求文件
modelock-client.exe init --vreq-out 授权请求.vreq

# 4.2 把 .vreq 发给画师，画师返回 .vkit 后激活
modelock-client.exe activate --server http://<服务器IP>:8787 --code ML-XXXX

# 4.3 挂载并启动 VTS（默认 Steam 启动 + 监听校验）
modelock-client.exe mount --vkit 小樱-买家.vkit
```

## 5. 重点验证清单

| 检查项 | 预期结果 |
|---|---|
| mount 后 VTS 被拉起 | 任务管理器显示 VTS 的父进程是 `steam.exe` |
| VTS 模型列表 | 出现该模型，可加载，表情/动作正常 |
| 资源管理器访问模型目录 | 拒绝访问（只有授权 VTS 能读，目录枚举也拒绝） |
| 手动双击 VTS（非 Steam 启动） | 不被授权；mount 只接受父进程为 steam.exe 的新实例 |
| 已运行的旧 VTS 实例 | 不授权（只授权启动前快照之后出现的新实例） |
| 关闭客户端 / Ctrl+C | VTS 被终止（Job 或 TerminateProcess），模型目录被清理 |
| 把 .vkit 发给另一台机器 | 打不开（内容密钥绑定本机 KSP 私钥） |
| 同一激活码激活第二台设备 | 服务器返回 403 DEVICE_MISMATCH |

## 6. 常见问题

- **VTS 装在 Program Files 下**：StreamingAssets 需要写权限 → 以管理员身份运行客户端；
- **挂载失败“同名目录已存在”**：先删除/改名 `VTube Studio_Data\StreamingAssets\Live2DModels\<模型名>`；
- **Dokan 冲突**：先卸载旧 Dokan 再装官方最新版；
- **服务器在 Linux**：Windows 防火墙放行 8787 端口，客户端用局域网 IP；
- **Steam 未登录/离线**：Steam 启动会失败，先确保 Steam 在线；
- **杀毒软件拦截**：白名单加入 client 与 Dokan 组件（自签名程序常见）。

## 7. 调试手段

- 客户端日志：`RUST_LOG=debug modelock-client.exe mount ...`
- 服务器日志：终端直接可见每次请求；
- VTS 自身日志：`%APPDATA%\VTube Studio\logs`（排查模型加载问题）。
