# Fail2ban Standalone Manager (F2B Panel)

[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)
[![Bash](https://img.shields.io/badge/script-Bash-orange.svg)](https://www.gnu.org/software/bash/)

本脚本是 Fail2ban 管理脚本。

> 此脚本提取自该项目中的Fail2ban管理部分: [https://github.com/ISFZY/Xray-Auto](https://github.com/ISFZY/Xray-Auto)，在此基础上进行了修改、增加功能。


快速开始：

```bash
wget -N https://raw.githubusercontent.com/luoye663/fail2ban-Panel/main/f2b.sh && chmod +x f2b.sh && ./f2b.sh
```

```bash
===================================================
         Fail2ban 防火墙管理 (F2B Panel)          
===================================================
  状态: 运行中 (Active) | 共封禁: 24 IP
---------------------------------------------------
  1. 修改 最大重试次数 [3]
  2. 修改 初始封禁时长 [1h]
  3. 修改 监测时间窗口 [1h]
---------------------------------------------------
  4. Jail 维护中心 (List/Unban/Delete) ->
  5. 添加白名单   (Whitelist)
  6. 查看封禁日志 (Logs)
  7. 指数封禁设置 (Advanced) ->
---------------------------------------------------
  8. 开启/停止 Fail2ban 服务 (On/Off)
  9. 新增 服务检测 (Add Jail)
  10. 新增 端口扫描防护 (Recidive Jail)
  11. 防火墙后端 (IPtables/NFTables)
  12. 新增 端口扫描模板 (Scan Log)
  13. 设置 端口速率限制 (Rate Limit)
  14. 查看 底层防火墙拦截状态 (Firewall Check)
  0. 退出

```

## 🌟 核心特性

- **🚀 自动安装**：自动检测并安装 Fail2ban 及其依赖，自动识别 SSH 端口。
- **🛡️ 多维度防护**：
    - **顽固份子防护**：对多次违规的 IP 进行长期封禁。
    - **端口扫描防护**：基于系统日志识别并封禁扫描行为。
    - **连接速率限制**：利用 `iptables hashlimit` 实现物理层的连接监控。
- **⚙️ 智能后端适配**：自动识别并支持 `iptables`、`nftables`、`firewalld` 及 `ufw`。
- **📊 实时管理维护**：
    - 集中的 **Jail 维护中心**，管理封禁列表，一键解封。
    - 可视化查看底层防火墙（iptables/nft/ufw/firewalld）的真实拦截规则。
    - 快速切换防火墙后端（Banaction）。
- **📈 高级配置**：
    - **指数封禁（Bantime Increment）** 设置，让恶意攻击者被封禁时间呈指数级增长。
    - 简易白名单（Whitelist）管理。
- **🔍 日志审计**：格式化查看 Fail2ban 的 Ban/Unban 历史记录。

## 📋 系统要求

- **操作系统**：目前仅测试过 Debian 10+, Ubuntu 20.04+, CentOS 7+, RHEL 8+ (其他发行版可能需要自行微调)(某些最小系统可能缺少依赖，如 Rocky 9+,需要启动`CRB`后自行安装`epel-release`后再执行脚本安装)
- **权限**：必须以 `root` 或具有 `sudo` 权限的用户运行。
- **依赖**：脚本会自动处理 `fail2ban`、`rsyslog`、`python3-systemd` 等基础依赖。

## 🚀 快速开始

### 1. 下载并运行

在终端中执行以下命令：

```bash
wget -N https://raw.githubusercontent.com/luoye663/fail2ban-Panel/main/f2b.sh && chmod +x f2b.sh && ./f2b.sh
```


### 2. 功能导航

脚本启动后将进入交互式菜单：

1. **首次运行**：选择 `1` 进行 Fail2ban 的自动安装与基础加固。
2. **日常监控**：查看 `状态` 与 `Jail 维护中心`。
3. **增加防护**：使用 `9` (自定义 Jail) 或 `10` (顽固份子防护) 增强服务器安全性。
4. **底层检查**：使用 `14` 验证防火墙规则是否生效。

## 🛠️ 详细功能与使用指南

### 1. 基础配置管理 (选项 1-3)
- **最大重试次数 (maxretry)**：在监测窗口内，超过此尝试次数即封禁。
- **初始封禁时长 (bantime)**：默认封禁时间（如 1h, 1d）。
- **监测时间窗口 (findtime)**：统计重试次数的时间范畴。

### 2. Jail 维护中心 (选项 4)
这是脚本的核心管理模块：
- **查看状态**：显示所有 Jail（如 sshd, nginx）及其当前封禁的 IP 总数。
- **IP 解封**：选择对应 Jail 后，可输入 IP 手动将其从黑名单移除。
- **删除 Jail**：永久从系统中移除特定的自定义防护配置（不包括核心 sshd）。

### 3. 白名单管理 (选项 5)
- 支持添加单个 IP 或 CIDR 网段（如 `1.2.3.4` 或 `192.168.1.0/24`）。
- **自动建议**：默认会显示当前的 SSH 登录 IP，方便一键信任，防止误封。

### 4. 高级封禁策略 (选项 7/10)
- **指数封禁 (Advanced)**：开启后，频繁受罚的 IP 封禁时间会翻倍（1h -> 2h -> 4h...），最长可封禁 30 天。
- **Recidive Jail**：专门针对“二进宫”份子。它监控 Fail2ban 自身的日志，如果一个 IP 在短期内多次被封，则将其判为“顽固黑名单”并进行长期封禁。

### 5. 新增服务防护 (选项 9 - 自定义扩展)
脚本在初始化安装时仅默认激活 **sshd** 防护，但可将防护范围扩展到服务器上的其他服务。

**它是如何工作的？**
Fail2ban 的核心逻辑是“过滤器 (Filter)”。系统中安装 Fail2ban 后，自带了数个预置的过滤器（位于 `/etc/fail2ban/filter.d/`），涵盖了常见的 Web 登录、数据库尝试、邮件服务等。

**操作步骤详解：**
1.  **输入 Jail 名称**：为要保护的服务起个名字（如 `nginx-login`）。
2.  **选择过滤器 (Filter)**：脚本会扫描并列出 `/etc/fail2ban/filter.d/` 下的所有可用配置。只需输入对应的名称（如 `nginx-http-auth`）。
3.  **指定日志来源**：
    *   **常规文件**：手动指定日志路径（如 `/var/log/nginx/error.log`）。脚本会自动检测文件是否存在并给出建议。
    *   **Systemd Journal**：针对现代发行版，可以选择从系统日志流中直接读取，无需指定具体路径。
4.  **设定独立阈值**：可以为该服务单独设置不同于默认配置的 `maxretry`（重试次数）和 `bantime`（封禁时长）。

**意义**：这使得该脚本变成了一个**通用管理面板**。不再受限于脚本自带的服务，只要 Fail2ban 官方或社区提供了对应的 `.conf` 过滤器文件，就可以通过本脚本一键启用防护。 

### 6. 防火墙感知与联动 (选项 11/14)
- **后端切换**：可一键将封禁底层从 `iptables` 切换为 `nftables` 或 `firewalld`。
- **状态看板**：通过选项 14 可以直接查看防火墙（Firewall Command Line）中最真实的拦截数字，验证 Fail2ban 是否真正生效。

### 7. 端口速率限制 (选项 13) (实验性功能)
- 非 Fail2ban 功能，直接调用 `iptables hashlimit`。
- 设置每分钟允许的新建连接数。适用于应对极高频的 CC 攻击或高频扫描，在流量进入应用层前即被阻断。



