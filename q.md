# Remote-Manager 远程连接管理器
![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![Release](https://img.shields.io/badge/build-release-brightgreen.svg)

**一款基于 Rust 开发、轻量化、高性能、全终端交互式 RDP/SSH 统一连接管理工具**
（已修复：RDP 显示器切换、SCP 文件传输崩溃、命令拼接错误等所有已知问题）

---

## 📖 目录
- [项目初衷](#-项目初衷)
- [项目介绍](#-项目介绍)
- [核心功能](#-核心功能)
- [系统支持平台](#️-系统支持平台)
- [依赖环境](#-依赖环境)
- [项目获取](#-项目获取)
- [编译部署](#-编译部署)
- [极致压缩构建](#-极致压缩构建)
- [内置 trzsz 工具](#-内置trzsz工具关键)
- [完整使用教程](#-完整使用教程)
- [数据目录结构](#-数据目录结构)
- [安全设计](#️-安全设计)
- [常见问题与排查](#-常见问题与排查)
- [更新日志](#-更新日志)
- [开源协议](#-开源协议)

---

## 💡 项目初衷
在日常运维、多服务器管理场景中，长期面临以下痛点：
1. **工具碎片化**：RDP、SSH、文件传输工具分开使用，切换繁琐
2. **主机无统一管理**：IP、账号、密码分散记录，无快速检索
3. **Linux RDP 体验差**：FreeRDP 参数复杂，无配置保存功能
4. **SCP 传输不稳定**：命令易写错、进度条卡死、无可视化操作
5. **安全风险高**：闭源工具存在隐私泄露风险

**本工具解决所有问题**：
- Rust 编写，高性能、内存安全、单文件运行
- 整合 RDP + SSH + SCP 三大核心功能
- 密码 AES-256 加密存储，配置本地化
- 纯终端交互，零学习成本，服务器/桌面通用

---

## 📌 项目介绍
`remote-manager` 是**纯终端交互式远程管理工具**，专为 Linux 运维/IT 管理员设计。
基于 `xfreerdp3` + `OpenSSH` + `trzsz` 实现：
- ✅ Windows RDP 远程桌面（单/多显示器自由切换）
- ✅ Linux SSH 终端连接（密码/密钥双模式）
- ✅ SCP 稳定文件传输（无报错、无卡死）
- ✅ 批量主机检测、批量命令执行
- ✅ 主机配置加密管理、自动备份

---

## 🚀 核心功能（2025 稳定版）
### 1. 连接管理
- ✅ **RDP 连接**：单/多显示器精准控制、剪切板同步、自动重连
- ✅ **SSH 连接**：密码登录 + 密钥登录，自动部署 trzsz 传输工具
- ✅ **SCP 传输**：上传/下载可视化，**无命令报错、无 0B/s 卡死**
- ✅ 主机分页列表、搜索、最近连接排序

### 2. 配置与安全
- ✅ **AES-256-GCM 加密**：密码绝不明文落地
- ✅ 配置自动备份，防止丢失
- ✅ 文件权限隔离（0o600/0o755），安全可靠

### 3. 运维增强
- ✅ 批量端口检测：一键检查所有主机存活状态
- ✅ 批量 SSH 命令执行：多服务器统一运维
- ✅ 全自动依赖检测，缺失组件一键引导安装

### 4. 已修复关键问题
- ✅ RDP 单/多显示器参数错误（现在选择完全生效）
- ✅ SCP 传输 `stat "-"` 报错
- ✅ SCP 进度条卡死、0B/s 问题
- ✅ 命令拼接错误导致传输失败
- ✅ SSH 连接稳定性优化

---

## 🖥️ 系统支持平台
### 稳定运行
- ✅ Debian 12 / Ubuntu 22.04 / 24.04
- ✅ Pop!_OS 22.04 / 24.04
- ✅ Proxmox VE / LXC 容器
- ✅ 无桌面纯终端服务器

### 架构
- x86_64 (amd64) Linux
- 可轻松移植 ARM64

---

## 📦 依赖环境
程序**首次启动自动检测并提示安装**：
```bash
sudo apt install -y sshpass freerdp3-x11 scp coreutils pv
```

---

## 📥 项目获取
### 1. 新建项目
```bash
cargo new remote-manager
cd remote-manager
```

### 2. 替换源码
将 `src/main.rs` 替换为你提供的**完整修复版代码**

### 3. 配置 Cargo.toml
```toml
[package]
name = "remote-manager"
version = "0.1.0"
edition = "2021"

[dependencies]
base64 = "0.22"
serde = { version = "1.0", features = ["derive"] }
serde_yaml = "0.9"
chrono = { version = "0.4", features = ["local"] }
log = "0.4"
env_logger = "0.11"
aes-gcm = "0.10"
generic-array = "0.25"
hex = "0.4"
libc = "0.2"
```

---

## 🔨 编译部署
### 1. 安装 Rust（仅第一次）
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. 生成 trzsz base64 文件（必须）
创建 `build_trzsz_b64.sh` 并执行：
```bash
chmod +x build_trzsz_b64.sh
./build_trzsz_b64.sh
```

### 3. 正式编译（生产环境）
```bash
cargo build --release
```
运行文件：`target/release/remote-manager`

---

## 📉 极致压缩构建
适合 U 盘拷贝、内网分发：
```bash
# 安装工具
sudo apt install musl-tools upx
rustup target add x86_64-unknown-linux-musl

# 静态编译
cargo build --release --target x86_64-unknown-linux-musl

# 瘦身压缩
strip target/x86_64-unknown-linux-musl/release/remote-manager
upx -9 target/x86_64-unknown-linux-musl/release/remote-manager
```

---

## 📦 内置 trzsz 工具（关键）
程序**自动释放**文件传输工具，无需手动安装：
- `trz`：远程上传
- `tsz`：远程下载
- `trzsz`：整合传输核心

文件路径：
```
remote-manager-data/cache/
```

---

## 🎯 完整使用教程
### 1. 启动程序
```bash
./remote-manager
```

### 2. 主菜单
```
===================== 远程管理工具 ====================
1. 连接 RDP 主机
2. 连接 SSH 主机
3. 添加新主机
4. 编辑主机
5. 删除主机
6. SCP 文件传输
7. 批量执行命令
8. 配置管理
9. 批量检测主机连通性
0. 退出程序
=====================================================
```

---

### 3. 添加 RDP 主机（Windows）
1. 菜单输入 `3`
2. 类型：`1` (RDP)
3. 主机名：自定义
4. IP：支持简写（如输入 `10` → 自动补全 `192.168.1.10`）
5. 端口：默认 3389
6. 用户名：Administrator
7. 密码：自动加密
8. 共享目录：默认家目录

---

### 4. 连接 RDP（单/多显示器）
1. 菜单 `1` → 选择主机
2. **选择显示模式**：
   - `1` → 单显示器（精准生效）
   - `2` → 多显示器扩展模式

---

### 5. SCP 文件传输（已修复 100% 可用）
1. 菜单 `6`
2. 选择主机
3. 方向：
   - `1` 上传：本地 → 远程
   - `2` 下载：远程 → 本地
4. 输入路径 → 自动传输，带进度条
5. 提示 `✅ 传输成功` 完成

---

### 6. 批量检测主机
菜单 `9` → 自动扫描所有主机端口状态

---

## 📂 数据目录结构（绿色免安装）
```
remote-manager-data/
├── config/config.yaml   # 加密配置文件
├── ssh/known_hosts      # SSH 指纹
├── cache/               # 传输工具
└── logs/                # 运行日志
```
**迁移方法**：复制二进制文件 + data 目录即可。

---

## 🛡️ 安全设计
1. **AES-256-GCM 加密**：密码永不明文
2. **权限隔离**：配置文件 0o600，仅本人可见
3. **无云端上传**：所有数据本地存储
4. **自动备份**：修改配置自动生成 .bak

---

## ❌ 常见问题与排查
### 1. SCP 报错：stat "-" No such file
✅ **已修复**，使用新版代码完全解决

### 2. RDP 无论选单/多都变成多屏
✅ **已修复**，参数完全重写，选择立即生效

### 3. SSH 连接失败 (255)
- IP/端口错误
- 密码错误
- 密钥权限不对：`chmod 600 密钥文件`

### 4. 缺少依赖
```bash
sudo apt install -y sshpass freerdp3-x11 pv
```

---

## 📝 更新日志
### v1.0.0（稳定最终版）
- ✅ 修复 RDP 显示器参数错误
- ✅ 修复 SCP 传输命令拼接错误
- ✅ 修复 SCP 进度条卡死 0B/s
- ✅ 修复传输崩溃、报错问题
- ✅ 优化 SSH 连接逻辑
- ✅ 全流程可视化、无命令记忆成本

---

## 📜 开源协议
MIT License，可自由使用、修改、分发。
**禁止用于非法入侵、未授权远程操作**，责任自负。

---

## 🤝 反馈
如有问题，欢迎提交 Issue！
如果你觉得这个工具好用，欢迎 Star 支持！

---

## 📁 项目必需文件清单
```
remote-manager/
├── src/main.rs             # 你的完整修复版代码
├── Cargo.toml              # 依赖配置
├── build_trzsz_b64.sh      # 生成工具脚本
├── trz.b64                 # 必需
├── tsz.b64                 # 必需
└── trzsz.b64               # 必需
```
