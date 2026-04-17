use base64::engine::{general_purpose, Engine as _};
use chrono::Local;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::fs::{self, Permissions};
use std::io::{self, IsTerminal, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Once;
use std::time::Duration;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use generic_array::GenericArray;

// ==================== 🔐 全局常量 ====================
const APP_DIR: &str = "remote-manager-data";
const CONFIG_DIR: &str = "config";
const CACHE_DIR: &str = "cache";
const SSH_DIR: &str = "ssh";
const LOG_DIR: &str = "logs";
const CONFIG_FILE: &str = "config.yaml";
const LOG_FILE: &str = "remote-manager.log";
const SSH_CONNECT_TIMEOUT: &str = "2";
const CONNECT_TIMEOUT_SECS: u64 = 2;
const PAGE_SIZE: usize = 15;
const DEFAULT_IP_PREFIX: &str = "192.168.";
const DEFAULT_RDP_USER: &str = "Administrator";

const ENCRYPTION_KEY: &[u8; 32] = b"12345678901234561234567890123456";

// ==================== 🔥 内置二进制 (Base64) ====================
const TRZSZ_B64: &[u8] = include_bytes!("../trzsz.b64");
const TRZ_B64: &[u8] = include_bytes!("../trz.b64");
const TSZ_B64: &[u8] = include_bytes!("../tsz.b64");

// ==================== 📁 路径管理 ====================
fn get_base_dir() -> io::Result<PathBuf> {
    let exe_path = std::env::current_exe()
        .map_err(|e| io::Error::new(e.kind(), format!("无法获取程序路径: {}", e)))?;

    let bin_dir = exe_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "无法确定程序目录"))?
        .to_path_buf();

    let app_dir = bin_dir.join(APP_DIR);
    if !app_dir.exists() {
        fs::create_dir_all(&app_dir)?;
        #[cfg(unix)]
        fs::set_permissions(&app_dir, Permissions::from_mode(0o755))?;
    }
    Ok(app_dir)
}

fn mk_dir(name: &str) -> io::Result<PathBuf> {
    let p = get_base_dir()?.join(name);
    if !p.exists() {
        fs::create_dir_all(&p)?;
    }
    Ok(p)
}
fn get_config_dir() -> io::Result<PathBuf> {
    mk_dir(CONFIG_DIR)
}
fn get_cache_dir() -> io::Result<PathBuf> {
    mk_dir(CACHE_DIR)
}
fn get_ssh_dir() -> io::Result<PathBuf> {
    mk_dir(SSH_DIR)
}
fn get_log_dir() -> io::Result<PathBuf> {
    mk_dir(LOG_DIR)
}
fn get_known_hosts_path() -> io::Result<PathBuf> {
    get_ssh_dir().map(|p| p.join("known_hosts"))
}
fn get_config_path() -> io::Result<PathBuf> {
    get_config_dir().map(|p| p.join(CONFIG_FILE))
}
fn get_log_path() -> io::Result<PathBuf> {
    get_log_dir().map(|p| p.join(LOG_FILE))
}
fn get_home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("~"))
}

// ==================== 依赖检查与安装 ====================
fn check_and_install_deps() -> io::Result<()> {
    println!("🔍 检查系统依赖工具...");

    let deps = [
        ("sshpass", "sshpass"),
        ("xfreerdp3", "freerdp3-dev"),
        ("scp", "openssh-client"),
        ("base64", "coreutils"),
        ("pv", "pv"),
    ];

    let mut need_install = Vec::new();

    for (cmd, pkg) in deps {
        if !is_command_available(cmd) {
            println!("⚠️  未找到: {}", cmd);
            need_install.push(pkg);
        }
    }

    if need_install.is_empty() {
        println!("✅ 所有依赖已安装");
        return Ok(());
    }

    println!("\n📦 需要安装: {}", need_install.join(" "));
    if confirm("是否自动安装 (需要 sudo 权限)？") {
        let status = Command::new("sudo").arg("apt").arg("update").status()?;

        if !status.success() {
            eprintln!("❌ apt update 失败");
            return Ok(());
        }

        let mut cmd = Command::new("sudo");
        cmd.arg("apt").arg("install").arg("-y");
        cmd.args(&need_install);
        let status = cmd.status()?;

        if status.success() {
            println!("✅ 依赖安装完成");
        } else {
            eprintln!(
                "❌ 安装失败，请手动执行: sudo apt install -y {}",
                need_install.join(" ")
            );
        }
    } else {
        eprintln!("❌ 部分依赖缺失，功能可能无法正常使用");
    }

    Ok(())
}

fn is_command_available(cmd: &str) -> bool {
    #[cfg(unix)]
    let status = Command::new("which")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    #[cfg(windows)]
    let status = Command::new("where")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    status.map(|s| s.success()).unwrap_or(false)
}

// ==================== 日志系统 ====================
static LOGGER_INIT: Once = Once::new();
fn init_logger() -> io::Result<()> {
    let log_path = get_log_path()?;
    LOGGER_INIT.call_once(|| {
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok();

        if let Some(f) = file {
            let _ = env_logger::builder()
                .format(|buf, record| {
                    writeln!(
                        buf,
                        "[{}] [{}] {}",
                        Local::now().format("%Y-%m-%d %H:%M:%S"),
                        record.level(),
                        record.args()
                    )
                })
                .target(env_logger::Target::Pipe(Box::new(f)))
                .filter_level(log::LevelFilter::Info)
                .try_init();
        }
    });

    #[cfg(unix)]
    if log_path.exists() {
        let _ = fs::set_permissions(&log_path, Permissions::from_mode(0o600));
    }

    Ok(())
}

fn log_action(action: &str, detail: &str) {
    info!("{}: {}", action, detail);
    println!("📝 [{}] {}", action, detail);
}

// ==================== 安全工具 (AES-GCM) ====================
fn secure_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok(())
}

fn encrypt_password(pwd: &str) -> String {
    if pwd.is_empty() {
        return String::new();
    }

    let key = GenericArray::from_slice(ENCRYPTION_KEY);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypted = cipher.encrypt(&nonce, pwd.as_bytes()).unwrap_or_default();

    let mut result = Vec::new();
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);

    hex::encode(result)
}

fn decrypt_password(encoded: &str) -> io::Result<String> {
    if encoded.is_empty() {
        return Ok(String::new());
    }

    let data = hex::decode(encoded)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "密码解密失败"))?;

    if data.len() < 12 {
        return Ok(String::new());
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let key = GenericArray::from_slice(ENCRYPTION_KEY);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "密码解密失败"))?;

    String::from_utf8(plaintext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "密码格式错误"))
}

// ==================== 工具释放 ====================
fn release_tools() -> io::Result<()> {
    let dir = get_cache_dir()?;
    for (name, b64) in [("trzsz", TRZSZ_B64), ("trz", TRZ_B64), ("tsz", TSZ_B64)] {
        let path = dir.join(name);
        if !path.exists() {
            let decoded = general_purpose::STANDARD.decode(b64).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("解码 {} 失败: {}", name, e),
                )
            })?;
            fs::write(&path, &decoded)?;
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&path, perms)?;
        }
    }
    Ok(())
}

// ==================== 数据结构 ====================
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HostType {
    Rdp,
    Ssh,
}

impl HostType {
    fn default_port(&self) -> u16 {
        match self {
            HostType::Rdp => 3389,
            HostType::Ssh => 50022,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            HostType::Rdp => "RDP",
            HostType::Ssh => "SSH",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Host {
    name: String,
    ip: String,
    port: u16,
    username: String,

    #[serde(default)]
    password_encrypted: String,

    #[serde(default)]
    drive: String,

    #[serde(default)]
    key_path: String,

    host_type: HostType,

    #[serde(default)]
    created_at: String,

    #[serde(default)]
    updated_at: String,

    #[serde(default)]
    last_connected_at: u64,
}

impl Host {
    fn password(&self) -> io::Result<String> {
        decrypt_password(&self.password_encrypted)
    }

    fn set_password(&mut self, pwd: &str) {
        self.password_encrypted = encrypt_password(pwd);
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    hosts: Vec<Host>,
}

// ==================== 配置管理 ====================
fn load_config() -> io::Result<Config> {
    let p = get_config_path()?;
    if !p.exists() {
        return Ok(Config::default());
    }

    let c = fs::read_to_string(&p)
        .map_err(|e| io::Error::new(e.kind(), format!("读取配置失败: {}", e)))?;

    serde_yaml::from_str(&c)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("解析配置失败: {}", e)))
}

fn save_config(cfg: &Config) -> io::Result<()> {
    let p = get_config_path()?;
    let tmp = p.with_extension("yaml.tmp");

    let content = serde_yaml::to_string(cfg).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("序列化配置失败: {}", e))
    })?;

    fs::write(&tmp, &content)?;
    secure_file(&tmp)?;

    if p.exists() {
        let backup = p.with_extension("yaml.bak");
        let _ = fs::copy(&p, backup);
    }

    fs::rename(&tmp, &p)?;
    Ok(())
}

fn backup_config() -> io::Result<()> {
    let s = get_config_path()?;
    if !s.exists() {
        println!("⚠️  配置文件不存在");
        return Ok(());
    }
    let d = s.with_extension(format!("yaml{}.bak", Local::now().format("_%Y%m%d_%H%M%S")));
    fs::copy(&s, &d)?;
    println!("✅ 配置已备份: {}", d.display());
    Ok(())
}

// ==================== 输入工具 ====================
fn read_line(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn read_password(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;

    #[cfg(unix)]
    if io::stdin().is_terminal() {
        let _ = Command::new("stty").args(["-echo", "icanon"]).status();
    }

    let mut pwd = String::new();
    io::stdin().read_line(&mut pwd)?;

    #[cfg(unix)]
    if io::stdin().is_terminal() {
        let _ = Command::new("stty").args(["echo", "icanon"]).status();
    }

    println!();
    Ok(pwd.trim().to_string())
}

fn confirm(prompt: &str) -> bool {
    match read_line(&format!("{} [y/N]: ", prompt)) {
        Ok(ans) => matches!(ans.to_lowercase().as_str(), "y" | "yes"),
        Err(_) => false,
    }
}

// ==================== IP 智能拼接 ====================
fn normalize_ip(input: &str) -> io::Result<String> {
    let input = input.trim();
    if input.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "IP 不能为空"));
    }

    if input.parse::<Ipv4Addr>().is_ok() {
        return Ok(input.to_string());
    }

    let candidate = if input.starts_with(DEFAULT_IP_PREFIX) {
        input.to_string()
    } else {
        format!("{}{}", DEFAULT_IP_PREFIX, input)
    };

    if candidate.parse::<Ipv4Addr>().is_ok() {
        Ok(candidate)
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "IP 格式不合法"))
    }
}

// ==================== 主机选择 ====================
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

fn select_host_interactive(cfg: &Config, host_type: Option<HostType>) -> io::Result<Option<usize>> {
    let mut hosts: Vec<(usize, &Host)> = cfg
        .hosts
        .iter()
        .enumerate()
        .filter(|(_, h)| host_type.is_none_or(|t| h.host_type == t))
        .collect();

    hosts.sort_by(|(_, a), (_, b)| b.last_connected_at.cmp(&a.last_connected_at));

    if hosts.is_empty() {
        println!("📭 没有可用主机");
        return Ok(None);
    }

    let total = hosts.len();
    let total_pages = (total - 1) / PAGE_SIZE + 1;
    let mut page = 0;

    loop {
        let start = page * PAGE_SIZE;
        let end = std::cmp::min(start + PAGE_SIZE, total);
        let current = &hosts[start..end];

        println!(
            "\n=== 主机列表 [第 {}/{} 页，共 {} 台] ===",
            page + 1,
            total_pages,
            total
        );
        println!(
            "{:<4} {:<8} {:<20} {:<16} {:<6} {:<12} 最近连接",
            "ID", "类型", "名称", "地址", "端口", "用户"
        );
        println!("{}", "─".repeat(85));

        for (i, (_, h)) in current.iter().enumerate() {
            let last = if h.last_connected_at > 0 {
                chrono::DateTime::from_timestamp(h.last_connected_at as i64, 0)
                    .map(|dt| dt.format("%m-%d %H:%M").to_string())
                    .unwrap_or_default()
            } else {
                "从未".to_string()
            };

            println!(
                "{:<4} {:<8} {:<20} {:<16} {:<6} {:<12} {}",
                i + 1,
                h.host_type.as_str(),
                truncate(&h.name, 20),
                truncate(&h.ip, 16),
                h.port,
                truncate(&h.username, 12),
                last
            );
        }

        let prompt = if total_pages > 1 {
            "输入序号 (0 取消，p 上一页，n 下一页，s 搜索): "
        } else {
            "输入序号 (0 取消，s 搜索): "
        };

        match read_line(prompt)? {
            s if s == "0" => return Ok(None),
            s if s.eq_ignore_ascii_case("p") => {
                if page > 0 {
                    page -= 1;
                } else {
                    println!("⚠️  已是首页");
                }
            }
            s if s.eq_ignore_ascii_case("n") => {
                if page + 1 < total_pages {
                    page += 1;
                } else {
                    println!("⚠️  已是末页");
                }
            }
            s if s.eq_ignore_ascii_case("s") => {
                let kw = read_line("🔍 搜索关键词 (名称/IP): ")?;
                return search_and_select(cfg, host_type, &kw);
            }
            s => {
                if let Ok(idx) = s.parse::<usize>() {
                    if idx > 0 && idx <= current.len() {
                        return Ok(Some(current[idx - 1].0));
                    }
                }
                println!("❌ 无效输入");
            }
        }
    }
}

fn search_and_select(
    cfg: &Config,
    host_type: Option<HostType>,
    keyword: &str,
) -> io::Result<Option<usize>> {
    let results: Vec<(usize, &Host)> = cfg
        .hosts
        .iter()
        .enumerate()
        .filter(|(_, h)| host_type.is_none_or(|t| h.host_type == t))
        .filter(|(_, h)| keyword.is_empty() || h.name.contains(keyword) || h.ip.contains(keyword))
        .collect();

    if results.is_empty() {
        println!("📭 无匹配结果");
        return Ok(None);
    }

    println!("\n=== 搜索结果 ({} 台) ===", results.len());
    println!(
        "{:<4} {:<8} {:<20} {:<16} {:<6} {:<12} 最近连接",
        "ID", "类型", "名称", "地址", "端口", "用户"
    );
    println!("{}", "─".repeat(75));

    for (i, (_, h)) in results.iter().enumerate() {
        println!(
            "{:<4} {:<8} {:<20} {:<16} {:<6} {:<12}",
            i + 1,
            h.host_type.as_str(),
            truncate(&h.name, 20),
            truncate(&h.ip, 16),
            h.port,
            truncate(&h.username, 12)
        );
    }

    loop {
        match read_line("输入序号 (0 返回): ")? {
            s if s == "0" => return Ok(None),
            s => {
                if let Ok(idx) = s.parse::<usize>() {
                    if idx > 0 && idx <= results.len() {
                        return Ok(Some(results[idx - 1].0));
                    }
                }
                println!("❌ 无效序号");
            }
        }
    }
}

// ==================== 主机管理 ====================
fn add_host(cfg: &mut Config) -> io::Result<()> {
    println!("\n=== 添加新主机 ===");

    let host_type = match read_line("类型 (1=RDP / 2=SSH): ")?.as_str() {
        "1" => HostType::Rdp,
        _ => HostType::Ssh,
    };

    let name = read_line("主机名称: ")?;
    if name.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "名称不能为空"));
    }

    let ip_input = read_line(&format!("IP 地址 [{}]: ", DEFAULT_IP_PREFIX))?;
    let ip = normalize_ip(&ip_input)?;

    let port = read_line(&format!("端口 (默认 {}): ", host_type.default_port()))?
        .parse::<u16>()
        .unwrap_or_else(|_| host_type.default_port());

    let username_default = if host_type == HostType::Rdp {
        DEFAULT_RDP_USER
    } else {
        ""
    };
    let username = read_line(&format!("用户名 [{}]: ", username_default))?;
    let username = if username.is_empty() {
        username_default.to_string()
    } else {
        username
    };

    let password = read_password("密码 (留空=密钥认证): ")?;

    let mut drive = String::new();
    let mut key_path = String::new();

    match host_type {
        HostType::Rdp => {
            drive = read_line("本地共享目录 (回车=家目录): ")?;
            if drive.is_empty() {
                drive = get_home_dir().to_string_lossy().to_string();
            }
        }
        HostType::Ssh => {
            key_path = read_line("SSH 密钥 (回车=~/.ssh/id_ed25519): ")?;
            if key_path.is_empty() {
                key_path = get_home_dir()
                    .join(".ssh/id_ed25519")
                    .to_string_lossy()
                    .to_string();
            }
        }
    }

    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mut host = Host {
        name,
        ip,
        port,
        username,
        password_encrypted: String::new(),
        drive,
        key_path,
        host_type,
        created_at: now.clone(),
        updated_at: now,
        last_connected_at: 0,
    };

    if !password.is_empty() {
        host.set_password(&password);
    }

    cfg.hosts.push(host);
    save_config(cfg)?;
    log_action("添加主机", &cfg.hosts.last().unwrap().name);
    println!("✅ 主机添加成功！");
    Ok(())
}

fn edit_host(cfg: &mut Config) -> io::Result<()> {
    let idx = match select_host_interactive(cfg, None)? {
        Some(i) => i,
        None => return Ok(()),
    };

    let mut host = cfg.hosts[idx].clone();
    println!("\n=== 编辑主机: {} ===", host.name);

    let new_name = read_line(&format!("名称 [{}]: ", host.name))?;
    let new_ip = read_line(&format!("IP [{}]: ", host.ip))?;
    let new_port = read_line(&format!("端口 [{}]: ", host.port))?;
    let new_user = read_line(&format!("用户名 [{}]: ", host.username))?;

    if !new_name.is_empty() {
        host.name = new_name;
    }
    if !new_ip.is_empty() {
        host.ip = normalize_ip(&new_ip)?;
    }
    if let Ok(p) = new_port.parse::<u16>() {
        host.port = p;
    }
    if !new_user.is_empty() {
        host.username = new_user;
    }

    if confirm("是否更新密码？") {
        let pwd = read_password("新密码 (留空=清空): ")?;
        if pwd.is_empty() {
            host.password_encrypted.clear();
        } else {
            host.set_password(&pwd);
        }
    }

    match host.host_type {
        HostType::Rdp => {
            let nd = read_line(&format!("共享目录 [{}]: ", host.drive))?;
            if !nd.is_empty() {
                host.drive = nd;
            }
        }
        HostType::Ssh => {
            let nk = read_line(&format!("密钥路径 [{}]: ", host.key_path))?;
            if !nk.is_empty() {
                host.key_path = nk;
            }
        }
    }

    host.updated_at = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    cfg.hosts[idx] = host;
    save_config(cfg)?;
    log_action("编辑主机", &cfg.hosts[idx].name);
    println!("✅ 编辑完成！");
    Ok(())
}

fn delete_host(cfg: &mut Config) -> io::Result<()> {
    let idx = match select_host_interactive(cfg, None)? {
        Some(i) => i,
        None => return Ok(()),
    };

    let name = cfg.hosts[idx].name.clone();
    if !confirm(&format!("确认删除主机 '{}'？", name)) {
        println!("❌ 已取消");
        return Ok(());
    }

    cfg.hosts.remove(idx);
    save_config(cfg)?;
    log_action("删除主机", &name);
    println!("✅ 已删除: {}", name);
    Ok(())
}

// ==================== RDP 连接 ====================
fn select_rdp_features() -> io::Result<Vec<&'static str>> {
    println!("====== FreeRDP 连接工具 ======");
    println!("请选择需要启用的功能（可多选，空格分隔）：\n");
    println!("【1】全屏模式");
    println!("【2】剪切板同步");
    println!("【3】管理员(控制台)模式");
    println!("【4】性能优化（关闭特效）");
    println!("【5】自动重连");
    println!("================================\n");

    let input = read_line("输入选项(例如:1 2 5):")?;
    let selections: Vec<u8> = input
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();

    // 🔥 终极兼容参数（所有 xfreerdp3 通用，无任何语法错误）
    let mut args = vec!["/cert:ignore"];

    for s in selections {
        match s {
            1 => args.push("/f"),           // 1. 全屏（标准语法）
            2 => args.push("+clipboard"),   // 2. 剪切板（标准语法）
            3 => args.push("/console"),    // 3. 控制台/管理员模式（兼容最强）
            4 => {
                // 4. 性能优化（无错误标准参数）
                args.push("-wallpaper");
                args.push("-themes");
            }
            5 => args.push("+auto-reconnect"), // 5. 自动重连（标准语法）
            _ => {}
        }
    }

    Ok(args)
}




fn spawn_daemon(cmd: &mut Command) -> io::Result<()> {
    
    cmd.stdin(Stdio::null())
       .stdout(Stdio::null())
       .stderr(Stdio::null());

    
    #[cfg(unix)]
    unsafe {
        use libc::{fork, setsid};
        // 第一次 fork
        match fork() {
            // 🔥 修复：删除多余 return
            -1 => Err(io::Error::last_os_error()),
            0 => {
                // 子进程：新建会话，脱离父终端
                setsid();
                // 第二次 fork，彻底失去会话控制
                match fork() {
                    -1 => std::process::exit(1),
                    0 => {
                        // 孙进程：真正执行 RDP，完全独立
                        let _ = cmd.spawn();
                        std::process::exit(0);
                    }
                    _ => std::process::exit(0),
                }
            }
            // 🔥 修复：删除多余 return
            _ => Ok(()),
        }
    }

    // Windows 备用逻辑
    #[cfg(windows)]
    {
        cmd.spawn()?;
        Ok(())
    }
}

fn connect_rdp(cfg: &mut Config) -> io::Result<()> {
    let idx = match select_host_interactive(cfg, Some(HostType::Rdp))? {
        Some(i) => i,
        None => return Ok(()),
    };

    // 更新连接时间
    cfg.hosts[idx].last_connected_at = Local::now().timestamp() as u64;
    save_config(cfg)?;

    let host = &cfg.hosts[idx];
    let rdp_args = select_rdp_features()?;
    let password = host.password()?;

    log_action("RDP 连接", &format!("{}@{}", host.username, host.ip));

    // 依赖检查
    if !is_command_available("xfreerdp3") {
        eprintln!("\n❌ 未安装 xfreerdp3");
        eprintln!("✅ 安装命令: sudo apt install freerdp3-x11");
        return Ok(());
    }

    // 构建 RDP 命令
    let mut cmd = Command::new("xfreerdp3");
    cmd.args(rdp_args)
        .arg(format!("/v:{}", host.ip))
        .arg(format!("/u:{}", host.username))
        .arg(format!("/p:{}", password));

    // 🔥 核心：永久后台守护执行（退出主程序/终端，RDP 不退出）
    spawn_daemon(&mut cmd)?;

    println!("🚀 RDP 已永久后台启动 ✅");
    println!("ℹ️ 关闭主程序/终端不影响，直接关闭 RDP 窗口断开连接\n");

    Ok(())
}
// ==================== 批量检测主机端口连通性 ====================
fn check_all_hosts_connectivity(cfg: &Config) -> io::Result<()> {
    let hosts = &cfg.hosts;
    if hosts.is_empty() {
        println!("📭 未添加任何主机！");
        return Ok(());
    }

    println!(
        "\n🚀 批量检测主机TCP端口连通性（超时{}秒）",
        CONNECT_TIMEOUT_SECS
    );
    println!("{}", "─".repeat(60));

    let mut success_ips = Vec::new();
    let mut failed_ips = Vec::new();
    let timeout = Duration::from_secs(CONNECT_TIMEOUT_SECS);

    for host in hosts {
        let addr = format!("{}:{}", host.ip, host.port);
        print!("检测 {} ({})...", host.ip, host.host_type.as_str());
        io::stdout().flush()?;

        let socket_addr = match addr.parse::<SocketAddr>() {
            Ok(s) => s,
            Err(_) => {
                println!("❌ IP格式错误");
                failed_ips.push(host.ip.clone());
                continue;
            }
        };

        match TcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(_) => {
                println!("✅ 成功");
                success_ips.push(host.ip.clone());
            }
            Err(_) => {
                println!("❌ 失败");
                failed_ips.push(host.ip.clone());
            }
        }
    }

    println!("{}", "─".repeat(60));
    println!("📊 检测完成：");
    println!("总主机数：{}", hosts.len());
    println!("✅ 连通成功：{} 个", success_ips.len());
    println!("❌ 连通失败：{} 个", failed_ips.len());
    println!();

    if !success_ips.is_empty() {
        println!("✅ 成功IP：{}", success_ips.join(" | "));
    }
    if !failed_ips.is_empty() {
        println!("❌ 失败IP：{}", failed_ips.join(" | "));
    }
    println!();

    Ok(())
}

// ==================== SSH 连接（已优化提速） ====================
fn connect_ssh(cfg: &mut Config) -> io::Result<()> {
    let _ = release_tools();

    let idx = match select_host_interactive(cfg, Some(HostType::Ssh))? {
        Some(i) => i,
        None => return Ok(()),
    };

    cfg.hosts[idx].last_connected_at = Local::now().timestamp() as u64;
    let _ = save_config(cfg);
    let h = &cfg.hosts[idx].clone();
    let password = h.password().unwrap_or_default();

    let kh_path = get_known_hosts_path()?;
    let kh_path_str = kh_path.to_string_lossy();

    log_action("连接 SSH", &format!("{}@{}", h.username, h.ip));

    if !password.is_empty() {
        if let Ok(false) = check_remote_trzsz(h, &password, &kh_path_str) {
            println!("📦 部署 trzsz 工具...");
            let _ = deploy_trzsz_to_remote(h, &password, &kh_path_str);
        }
    }

    let trzsz_bin = get_cache_dir()?.join("trzsz");
    let mut cmd = Command::new(&trzsz_bin);
    cmd.arg("ssh")
        .arg("-p")
        .arg(h.port.to_string())
        .arg("-o")
        .arg(format!("ConnectTimeout={}", SSH_CONNECT_TIMEOUT))
        .arg("-o")
        .arg("CheckHostIP=no")
        .arg("-o")
        .arg("GSSAPIAuthentication=no")
        .arg("-o")
        .arg("ControlMaster=auto")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh_path_str))
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new");

    let has_key = !h.key_path.is_empty() && Path::new(&h.key_path).exists();
    if has_key {
        cmd.arg("-i")
            .arg(&h.key_path)
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-o")
            .arg("PreferredAuthentications=publickey,password");
    } else {
        cmd.arg("-o")
            .arg("PreferredAuthentications=password,publickey");
    }

    if !password.is_empty() {
        cmd.env("SSHPASS", &password).env("TRZSZ_PWD", &password);
    }

    cmd.arg(format!("{}@{}", h.username, h.ip));
    println!("🔌 连接中... Ctrl+] 退出");

    let status = cmd.status()?;
    if !status.success() && status.code() == Some(255) {
        eprintln!("⚠️  连接失败：IP/端口/密码错误");
    }

    Ok(())
}

fn check_remote_trzsz(h: &Host, password: &str, kh_path: &str) -> io::Result<bool> {
    let out = Command::new("sshpass")
        .arg("-p")
        .arg(password)
        .arg("ssh")
        .args(["-p", &h.port.to_string(), "-o", "ConnectTimeout=2"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh_path))
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg(format!("{}@{}", h.username, h.ip))
        .arg("test -x ~/.local/bin/trz && test -x ~/.local/bin/tsz && echo OK")
        .output()?;

    Ok(out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "OK")
}

fn deploy_trzsz_to_remote(h: &Host, password: &str, kh_path: &str) -> io::Result<()> {
    let _ = run_ssh_cmd(h, password, "mkdir -p ~/.local/bin", kh_path);

    for (name, b64) in [("trz", TRZ_B64), ("tsz", TSZ_B64)] {
        let b64_str = general_purpose::STANDARD.encode(b64);
        let cmd = format!(
            "echo '{}' | base64 -d > ~/.local/bin/{} && chmod +x ~/.local/bin/{}",
            b64_str, name, name
        );
        let _ = run_ssh_cmd(h, password, &cmd, kh_path);
    }

    println!("✅ trzsz 部署完成");
    Ok(())
}

fn run_ssh_cmd(h: &Host, password: &str, cmd_str: &str, kh_path: &str) -> io::Result<ExitStatus> {
    Command::new("sshpass")
        .arg("-p")
        .arg(password)
        .arg("ssh")
        .args(["-p", &h.port.to_string(), "-o", "ConnectTimeout=5"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh_path))
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg(format!("{}@{}", h.username, h.ip))
        .arg(cmd_str)
        .status()
}

// ==================== SCP 文件传输（带进度条+提速） ====================
fn scp_transfer(cfg: &Config) -> io::Result<()> {
    let idx = match select_host_interactive(cfg, Some(HostType::Ssh))? {
        Some(i) => i,
        None => return Ok(()),
    };

    let h = &cfg.hosts[idx];
    let password = h.password().unwrap_or_default();
    let kh_path = get_known_hosts_path()?;
    let kh_path_str = kh_path.to_string_lossy();

    let mode = read_line("方向 (1=上传 / 2=下载): ")?;
    let local = read_line("本地路径: ")?;
    let remote = read_line("远程路径 (默认 ~/): ")?;
    let rp = if remote.is_empty() { "~/" } else { &remote };

    let port_str = h.port.to_string();
    let known_hosts_opt = format!("UserKnownHostsFile={kh_path_str}");

    let scp_args = [
        "-P",
        &port_str,
        "-r",
        "-o",
        "ConnectTimeout=2",
        "-o",
        "CheckHostIP=no",
        "-o",
        "GSSAPIAuthentication=no",
        "-o",
        &known_hosts_opt,
        "-o",
        "StrictHostKeyChecking=accept-new",
    ];

    let has_pv = is_command_available("pv");
    println!(
        "{}",
        if has_pv {
            "📊 启用传输进度条"
        } else {
            "⚠️  未安装pv，无进度条"
        }
    );

    let status = if mode == "1" {
        if has_pv {
            // 修复：合并嵌套 format!
            let cmd = format!(
                "pv '{local}' | sshpass -p '{password}' scp {} - '{h}@{ip}:{rp}'",
                scp_args.join(" "),
                h = h.username,
                ip = h.ip
            );
            Command::new("sh").arg("-c").arg(cmd).status()
        } else {
            Command::new("sshpass")
                .arg("-p")
                .arg(&password)
                .arg("scp")
                .args(scp_args) // 修复：移除不必要的 &
                .arg(&local)
                .arg(format!("{}@{}:{rp}", h.username, h.ip))
                .status()
        }
    } else {
        if has_pv {
            // 修复：合并嵌套 format!
            let cmd = format!(
                "sshpass -p '{password}' scp {} {h}@{ip}:{rp} - | pv > '{local}'",
                scp_args.join(" "),
                h = h.username,
                ip = h.ip
            );
            Command::new("sh").arg("-c").arg(cmd).status()
        } else {
            Command::new("sshpass")
                .arg("-p")
                .arg(&password)
                .arg("scp")
                .args(scp_args) // 修复：移除不必要的 &
                .arg(format!("{}@{}:{rp}", h.username, h.ip))
                .arg(&local)
                .status()
        }
    };

    if status?.success() {
        println!("✅ 传输成功");
    } else {
        eprintln!("❌ 传输失败");
    }

    Ok(())
}
// ==================== 批量执行 ====================
fn batch_exec(cfg: &Config) -> io::Result<()> {
    println!("\n=== 批量执行命令 ===");

    let kh_path = get_known_hosts_path()?;
    let kh_path_str = kh_path.to_string_lossy();

    let targets: Vec<&Host> = cfg
        .hosts
        .iter()
        .filter(|h| h.host_type == HostType::Ssh)
        .collect();

    if targets.is_empty() {
        println!("📭 无 SSH 主机");
        return Ok(());
    }

    println!("\n可用主机：");
    for (i, h) in targets.iter().enumerate() {
        println!("{}. {}@{}:{}", i + 1, h.username, h.ip, h.port);
    }

    let sel = read_line("选择 (1,3,5 或 all): ")?;
    let list: Vec<&Host> = if sel.trim().eq_ignore_ascii_case("all") {
        targets
    } else {
        sel.split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .filter(|&x| x > 0 && x <= targets.len())
            .map(|x| targets[x - 1])
            .collect()
    };

    if list.is_empty() {
        println!("❌ 未选择有效主机");
        return Ok(());
    }

    let command = read_line("命令: ")?;
    if command.is_empty() {
        println!("❌ 命令不能为空");
        return Ok(());
    }

    println!("\n🚀 开始执行...\n");
    for h in list {
        print!("[{}] ", h.name);
        io::stdout().flush()?;

        let pwd = h.password().unwrap_or_default();
        if !pwd.is_empty() {
            match run_ssh_cmd(h, &pwd, &command, &kh_path_str) {
                Ok(s) if s.success() => println!("✅"),
                _ => println!("❌"),
            }
        } else {
            let mut cmd = Command::new("ssh");
            cmd.arg("-p")
                .arg(h.port.to_string())
                .arg("-o")
                .arg("ConnectTimeout=3");

            if !h.key_path.is_empty() && Path::new(&h.key_path).exists() {
                cmd.arg("-i").arg(&h.key_path);
            }

            let res = cmd
                .arg(format!("{}@{}", h.username, h.ip))
                .arg(&command)
                .status();

            if res.map(|s| s.success()).unwrap_or(false) {
                println!("✅");
            } else {
                println!("❌");
            }
        }
    }

    Ok(())
}

// ==================== 配置菜单 ====================
fn config_menu(_cfg: &mut Config) -> io::Result<()> {
    loop {
        println!("\n=== 配置管理 ===");
        println!("1. 备份配置");
        println!("2. 查看数据路径");
        println!("0. 返回");

        match read_line("选择: ")? {
            s if s == "1" => backup_config()?,
            s if s == "2" => {
                println!("配置文件: {}", get_config_path()?.display());
                println!("SSH 指纹: {}", get_known_hosts_path()?.display());
                println!("缓存工具: {}", get_cache_dir()?.display());
                println!("日志文件: {}", get_log_path()?.display());
            }
            s if s == "0" => break,
            _ => println!("❌ 无效选择"),
        }
    }

    Ok(())
}

// ==================== 主循环 ====================
fn main() -> io::Result<()> {
    check_and_install_deps()?;
    init_logger()?;
    info!("=== remote-manager 启动 ===");

    println!("🚀 remote-manager 稳定版");
    println!("📂 数据目录: {}", get_base_dir()?.display());

    // 修复：unwrap_or_ → unwrap_or_else
    let mut cfg = load_config().unwrap_or_else(|e| {
        error!("配置加载失败: {}", e);
        Config::default()
    });

    loop {
        println!("\n{:=^55}", " remote-manager ");
        println!("1. 连接 RDP 主机");
        println!("2. 连接 SSH 主机");
        println!("3. 添加新主机");
        println!("4. 编辑主机");
        println!("5. 删除主机");
        println!("6. SCP 文件传输");
        println!("7. 批量执行命令");
        println!("8. 配置管理");
        println!("9. 批量检测主机连通性 ✅");
        println!("0. 退出");
        println!("{:=^55}", "");

        match read_line("请选择 (0-9): ")? {
            s if s == "1" => connect_rdp(&mut cfg)?,
            s if s == "2" => connect_ssh(&mut cfg)?,
            s if s == "3" => add_host(&mut cfg)?,
            s if s == "4" => edit_host(&mut cfg)?,
            s if s == "5" => delete_host(&mut cfg)?,
            s if s == "6" => scp_transfer(&cfg)?,
            s if s == "7" => batch_exec(&cfg)?,
            s if s == "8" => config_menu(&mut cfg)?,
            s if s == "9" => check_all_hosts_connectivity(&cfg)?,
            s if ["0", "q", "Q"].contains(&s.as_str()) => {
                info!("程序退出");
                println!("👋 再见！");
                break;
            }
            _ => println!("❌ 无效输入，请重试"),
        }
    }

    Ok(())
}
