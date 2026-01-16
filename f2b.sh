#!/bin/bash

# ==================================================================
# Project: Fail2ban Manager (F2B Panel)
# Version: 1.0.0
# Author: luoye663
# ==================================================================

# ------------------------------------------------------------------
# 一、颜色与基础配置 (Settings)
# ------------------------------------------------------------------

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PURPLE="\033[35m"; GRAY="\033[90m"; PLAIN="\033[0m"
INFO="${BLUE}[INFO]${PLAIN}"; OK="${GREEN}[OK]${PLAIN}"; ERR="${RED}[ERR]${PLAIN}"; WARN="${YELLOW}[WARN]${PLAIN}"

JAIL_FILE="/etc/fail2ban/jail.local"
JAIL_D_DIR="/etc/fail2ban/jail.d"

# ------------------------------------------------------------------
# 二、环境检查 (Checks)
# ------------------------------------------------------------------

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${ERR} 请使用 root 用户运行此脚本！"
        exit 1
    fi
}

# 服务管理兼容层 (Service Wrappers)
have_systemd() { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }

# 防火墙环境探测 (Firewall Detection)
detect_firewall() {
    if svc_active firewalld; then
        echo "firewalld"
    elif svc_active ufw && command -v ufw >/dev/null 2>&1 && ufw status | grep -qw "active"; then
        echo "ufw"
    elif command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
        echo "nftables-multiport"
    else
        echo "iptables-multiport"
    fi
}

detect_firewall_allports() {
    local base=$(detect_firewall)
    case "$base" in
        firewalld) echo "firewalld" ;;
        ufw) echo "ufw" ;;
        nftables-multiport) echo "nftables-allports" ;;
        *) echo "iptables-allports" ;;
    esac
}

svc_restart() { if have_systemd; then systemctl restart "$1"; else service "$1" restart; fi; }
svc_start()   { if have_systemd; then systemctl start "$1";   else service "$1" start; fi; }
svc_stop()    { if have_systemd; then systemctl stop "$1";    else service "$1" stop; fi; }
svc_enable()  { if have_systemd; then systemctl enable "$1";  elif command -v chkconfig >/dev/null; then chkconfig "$1" on; fi; }
svc_disable() { if have_systemd; then systemctl disable "$1"; elif command -v chkconfig >/dev/null; then chkconfig "$1" off; fi; }
svc_active()  { 
    if have_systemd; then 
        systemctl is-active "$1" >/dev/null 2>&1
    else 
        service "$1" status >/dev/null 2>&1
    fi
}

# ------------------------------------------------------------------
# 新增：输入验证函数
# ------------------------------------------------------------------

# IPv4/IPv6 验证（支持 CIDR）
validate_ip() {
    local ip=$1
    
    # IPv4 验证 (包括 CIDR)
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        local IFS='.'
        local -a octets=(${ip%%/*})
        for octet in "${octets[@]}"; do
            if [ "$octet" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    
    # IPv6 简单验证（支持压缩格式和 CIDR）
    if [[ $ip =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?$ ]] || [[ $ip == "::1" ]]; then
        return 0
    fi
    
    return 1
}

# 端口验证
validate_port() {
    local port=$1
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

# 时间格式验证 (支持 s/m/h/d/w)
validate_time() {
    local time=$1
    if [[ "$time" =~ ^[0-9]+[smhdw]?$ ]]; then
        return 0
    fi
    return 1
}

# ------------------------------------------------------------------
# 三、安装逻辑 (Installation)
# ------------------------------------------------------------------

install_f2b() {
    echo -e "${INFO} 正在准备安装 Fail2ban..."
    
    local pkg_manager=""
    local use_systemd=false
    if [ -d /run/systemd/system ]; then use_systemd=true; fi

    # 发行版判定
    if command -v apt-get >/dev/null; then
        pkg_manager="apt"
    elif command -v dnf >/dev/null; then
        pkg_manager="dnf"
    elif command -v yum >/dev/null; then
        pkg_manager="yum"
    else
        echo -e "${ERR} 不支持的系统包管理器 (仅支持 apt/dnf/yum)。"
        exit 1
    fi

    # SSH 端口检测与验证
    local current_ssh_port=$(grep -E "^[[:space:]]*Port[[:space:]]+" /etc/ssh/sshd_config | head -n 1 | awk '{print $2}' | tr -d '\r')
    if [[ ! "$current_ssh_port" =~ ^[0-9]+$ ]]; then
        current_ssh_port=22
    fi
    
    echo -e "${INFO} 检测到 SSH 端口: ${GREEN}${current_ssh_port}${PLAIN}"
    
    while true; do
        read -p "确认 Fail2ban 包含此端口? [${current_ssh_port}]: " confirm_port
        local target_port=${confirm_port:-$current_ssh_port}
        
        if validate_port "$target_port"; then
            break
        else
            echo -e "${ERR} 端口必须是 1-65535 之间的数字，请重新输入"
        fi
    done
    
    # 端口去重：如果端口是 22，就只写 22；否则写 custom,22
    local port_conf="$target_port"
    if [ "$target_port" != "22" ]; then
        port_conf="${target_port},22"
    fi

    echo -e "${INFO} 正在安装系统依赖..."
    if [ "$pkg_manager" == "apt" ]; then
        apt-get update -qq || { echo -e "${ERR} apt-get update 失败"; exit 1; }
        apt-get install -y fail2ban python3-systemd || { echo -e "${ERR} 安装失败"; exit 1; }
        [ "$use_systemd" != true ] && apt-get install -y rsyslog
    else
        $pkg_manager install -y epel-release || echo -e "${WARN} epel-release 安装失败（可能已存在）"
        $pkg_manager install -y fail2ban || { echo -e "${ERR} 安装失败"; exit 1; }
        [ "$use_systemd" != true ] && $pkg_manager install -y rsyslog
    fi

    local backend_val="systemd"
    [ "$use_systemd" != true ] && backend_val="auto"

    local fw_action=$(detect_firewall)
    local fw_all_action=$(detect_firewall_allports)
    echo -e "${INFO} 检测到活跃防火墙后端: ${GREEN}${fw_action}${PLAIN}"

    echo -e "${INFO} 写入初始配置 (Default Strategy: Balanced)..."
    mkdir -p "$JAIL_D_DIR"
    
    # 备份旧配置
    if [ -f "$JAIL_FILE" ]; then
        local bak_file="${JAIL_FILE}.bak.$(date +%F_%H%M%S)"
        echo -e "${INFO} 备份现有配置至: ${bak_file}"
        cp -a "$JAIL_FILE" "$bak_file" || echo -e "${WARN} 备份失败，继续..."
    fi

    # 写入配置文件（增加错误检查）
    cat > "$JAIL_FILE" <<EOF || { echo -e "${ERR} 配置文件写入失败"; exit 1; }
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 1h
bantime.increment = true
bantime.factor = 1
bantime.maxtime = 30d
findtime = 10m
maxretry = 5
backend = $backend_val
banaction = $fw_action
banaction_allports = $fw_all_action

[sshd]
enabled = true
port = $port_conf
mode = aggressive
EOF

    svc_restart rsyslog 2>/dev/null
    svc_enable fail2ban
    svc_restart fail2ban

    if svc_active fail2ban; then
        echo -e "${OK} Fail2ban 安装并启动成功！"
        sleep 2
    else
        echo -e "${ERR} 启动失败，请检查系统日志。"
        echo -e "${INFO} 尝试运行: journalctl -xeu fail2ban"
        exit 1
    fi
}

# ------------------------------------------------------------------
# 四、管理逻辑 (Management Functions)
# ------------------------------------------------------------------

# 读取配置（增加默认值处理）
get_conf() {
    local result=$(awk -F'=' -v k="$1" '
      $0 ~ "^[[:space:]]*"k"[[:space:]]*=" {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2);
        print $2; exit
      }' "$JAIL_FILE")
    echo "${result}"
}

# 修复版 set_conf: 增强转义处理，防止 sed 分隔符冲突
set_conf() {
    local key=$1 val=$2
    
    # 转义特殊字符：& / \ | 
    local safe_val=$(printf '%s\n' "$val" | sed 's/[&/\|]/\\&/g')
    
    # 创建临时文件时使用 PID 避免冲突
    local tmp_file="${JAIL_FILE}.tmp.$$"
    
    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$JAIL_FILE"; then
        # 存在则替换，使用备份
        sed -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${safe_val}|" "$JAIL_FILE" > "$tmp_file"
        if [ $? -eq 0 ]; then
            mv "$tmp_file" "$JAIL_FILE" || { echo -e "${ERR} 配置更新失败"; return 1; }
        else
            rm -f "$tmp_file"
            echo -e "${ERR} sed 执行失败"
            return 1
        fi
    else
        # 不存在则插入到 [DEFAULT] 后
        awk -v k="$key" -v v="$val" '
          BEGIN{done=0}
          /^\[DEFAULT\]/{print; if(!done){print k " = " v; done=1} next}
          {print}
          END{if(!done) print k " = " v}
        ' "$JAIL_FILE" > "$tmp_file"
        
        if [ $? -eq 0 ]; then
            mv "$tmp_file" "$JAIL_FILE" || { echo -e "${ERR} 配置更新失败"; return 1; }
        else
            rm -f "$tmp_file"
            echo -e "${ERR} awk 执行失败"
            return 1
        fi
    fi
    return 0
}

restart_f2b() {
    echo -e "${INFO} 正在重载配置..."
    
    # 先测试配置
    if ! fail2ban-client -t >/dev/null 2>&1; then
        echo -e "${ERR} 配置文件语法错误！"
        echo -e "${INFO} 请运行 'fail2ban-client -t' 查看详情"
        return 1
    fi

    if svc_restart fail2ban; then 
        echo -e "${OK} 配置已生效！"
        return 0
    else 
        echo -e "${ERR} 重启失败！"
        echo -e "${INFO} 请检查: journalctl -xeu fail2ban"
        return 1
    fi
}

get_status() {
    if svc_active fail2ban; then
        local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | awk -F':' '{print $2}' | tr -d ',' | sed 's/^[ \t]*//')
        local total=0
        for j in $jails; do 
            local count=$(fail2ban-client status "$j" 2>/dev/null | grep "Currently banned" | grep -o "[0-9]*")
            total=$((total + ${count:-0}))
        done
        echo -n -e "${GREEN}运行中 (Active)${PLAIN} | 共封禁: ${RED}${total}${PLAIN} IP"

        # 检测配置的防火墙是否真正活跃
        local act=$(get_conf "banaction")
        [ -z "$act" ] && act="iptables-multiport"
        local real_fw=$(detect_firewall)
        
        if [[ "$act" =~ "firewalld" && "$real_fw" != "firewalld" ]]; then
            echo -e " | ${RED}⚠️ 防火墙服务已停止${PLAIN}"
        elif [[ "$act" == "ufw" && "$real_fw" != "ufw" ]]; then
            echo -e " | ${RED}⚠️ UFW 未激活${PLAIN}"
        elif [[ "$act" =~ "nftables" && "$real_fw" != "nftables-multiport" ]]; then
            echo -e " | ${RED}⚠️ 后端状态异常${PLAIN}"
        else
            echo ""
        fi
    else
        echo -e "${RED}已停止 (Stopped)${PLAIN}"
    fi
}

# 新增：查看底层防火墙拦截规则
check_firewall_rules() {
    clear
    local act=$(get_conf "banaction")
    [ -z "$act" ] && act="iptables-multiport"
    
    local real_fw=$(detect_firewall)
    
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "${BLUE}       底层防火墙拦截规则 (Firewall Rules)        ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "当前配置的 Banaction: ${GREEN}${act}${PLAIN}"
    echo -e "系统运行的防火墙:     ${YELLOW}${real_fw}${PLAIN}"
    echo -e "---------------------------------------------------"

    # 一致性检查
    if [[ "$act" =~ "firewalld" && "$real_fw" != "firewalld" ]]; then
        echo -e "${WARN} ⚠️  冲突：配置为 firewalld 但系统未运行该服务！这会导致封禁失效。"
    elif [[ "$act" =~ "nftables" && "$real_fw" != "nftables-multiport" ]]; then
        echo -e "${WARN} ⚠️  冲突：配置为 nftables 但系统正在运行 ${real_fw}！"
    elif [[ "$act" =~ "iptables" && "$real_fw" == "firewalld" ]]; then
        echo -e "${WARN} ⚠️  警告：系统正在运行 firewalld，建议使用 firewalld 后端。"
    fi

    if [[ "$act" =~ "iptables" ]]; then
        if command -v iptables >/dev/null; then
            echo -e "${INFO} 正在查询 iptables 规则 (筛选 f2b 链)..."
            iptables -L -n | grep -E "^Chain f2b-|^target" -A 10 | grep -v "\-\-" 
            echo -e "\n${INFO} 提示：如果没有看到被封禁的 IP，说明相应 Jail 目前为空。"
        else
            echo -e "${ERR} 未找到 iptables 命令"
        fi
    elif [[ "$act" =~ "nftables" ]]; then
        if command -v nft >/dev/null; then
            echo -e "${INFO} 正在查询 nftables 规则 (f2b 相关)..."
            nft list ruleset | grep -E "table.*f2b|chain.*f2b|set.*f2b" -A 20
        else
            echo -e "${ERR} 未找到 nft 命令"
        fi
    elif [[ "$act" == "ufw" ]]; then
        if command -v ufw >/dev/null; then
            ufw status verbose
        else
            echo -e "${ERR} 未找到 ufw 命令"
        fi
    elif [[ "$act" == "firewalld" ]]; then
        if command -v firewall-cmd >/dev/null; then
            echo -e "${INFO} 正在查询 firewalld 规则..."
            firewall-cmd --direct --get-all-rules
        else
            echo -e "${ERR} 未找到 firewall-cmd 命令"
        fi
    else
        echo -e "${WARN} 暂不支持此后端的快速查看: ${act}"
    fi
    
    echo -e "---------------------------------------------------"
    read -n 1 -s -r -p "按任意键继续..."
}

# 核心：新增 Jail (独立文件，模块化)
add_custom_jail() {
    clear
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "${BLUE}         新增服务防护 (Add Custom Jail)            ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    
    while true; do
        read -p "Jail 名称 (如 nginx-auth / mysql / myapp): " jname
        
        # 安全修复：路径遍历校验 + 长度限制
        if [[ -z "$jname" ]]; then
            return
        elif [[ ! "$jname" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            echo -e "${ERR} 名称包含非法字符！只允许 字母/数字/-/_"
        elif [ ${#jname} -gt 50 ]; then
            echo -e "${ERR} 名称过长！最多 50 字符"
        else
            break
        fi
    done

    echo -e "\n${INFO} 系统可用 Filter 示例："
    ls /etc/fail2ban/filter.d 2>/dev/null | grep ".conf$" | sed 's/\.conf$//' |  { command -v column >/dev/null && column || cat; }
    echo -e "---------------------------------------------------"
    
    read -p "filter 名称 (默认与名称相同): " filter
    filter=${filter:-$jname}

    local use_journal="n"
    if [ -d /run/systemd/system ]; then
        read -p "是否从 systemd journal 读取日志? (y/n) [n]: " use_journal
    fi

    local log_conf=""
    if [[ "$use_journal" =~ ^[yY]$ ]]; then
        log_conf="backend = systemd"
    else
        # 循环强制输入有效 logpath
        while true; do
            read -p "日志路径 (如 /var/log/nginx/error.log): " lpath
            if [ -z "$lpath" ]; then
                echo -e "${ERR} 日志路径不能为空！"
                continue
            fi
            
            log_conf="logpath = $lpath"
            
            if [ ! -e "$lpath" ]; then
                echo -e "${WARN} 警告：文件 [$lpath] 未找到，Jail 可能无效。"
                read -p "是否继续? (y/n) [y]: " cont
                if [[ "$cont" =~ ^[nN]$ ]]; then
                    continue
                fi
            fi
            break
        done
    fi

    # 防踩坑检查
    if [ ! -f "/etc/fail2ban/filter.d/${filter}.conf" ]; then
        echo -e "${WARN} filter [${filter}] 不存在，jail 可能不会生效！"
        read -p "是否继续? (y/n) [y]: " cont
        [[ "$cont" =~ ^[nN]$ ]] && return
    fi

    # 使用更合理的默认值
    read -p "防护端口 (port) [默认 any]: " jport
    jport=${jport:-any}
    
    while true; do
        read -p "最大重试 (maxretry) [默认 5]: " jretry
        jretry=${jretry:-5}
        [[ "$jretry" =~ ^[0-9]+$ ]] && break
        echo -e "${ERR} 必须是数字！"
    done
    
    while true; do
        read -p "监测窗口 (findtime) [默认 10m]: " jfind
        jfind=${jfind:-10m}
        validate_time "$jfind" && break
        echo -e "${ERR} 格式错误！示例: 10m, 1h, 1d"
    done
    
    while true; do
        read -p "封禁时长 (bantime)  [默认 1h]: " jban
        jban=${jban:-1h}
        validate_time "$jban" && break
        echo -e "${ERR} 格式错误！示例: 1h, 1d, 1w"
    done

    mkdir -p "$JAIL_D_DIR"
    local target_file="${JAIL_D_DIR}/${jname}.local"
    
    cat > "$target_file" <<EOF || { echo -e "${ERR} 配置写入失败"; return 1; }
[$jname]
enabled = true
filter = ${filter}
${log_conf}
port = ${jport}
maxretry = ${jretry}
findtime = ${jfind}
bantime = ${jban}
EOF

    echo -e "\n${OK} 配置文件已写入: ${YELLOW}${target_file}${PLAIN}"
    if restart_f2b; then
        echo -e "${INFO} Jail 状态:"
        fail2ban-client status "$jname" 2>/dev/null || echo -e "${WARN} Jail 已添加但暂无数据。"
    fi
    read -n 1 -s -r -p "按任意键继续..."
}

# 新增：防扫/顽固份子 Jail (Recidive)
add_recidive_jail() {
    clear
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "${BLUE}      新增: 端口扫描/顽固份子防护 (Recidive)       ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "原理: 监控 Fail2ban 自身日志，对反复被其他 Jail 封禁的 IP 进行长期封禁。"
    echo -e "适用: 各种端口扫描器、暴力破解脚本的最终防线。"
    echo -e "---------------------------------------------------"
    
    local jname="recidive"
    local tfile="${JAIL_D_DIR}/${jname}.local"
    
    if [ -f "$tfile" ]; then
        echo -e "${WARN} Recidive Jail 已存在！"
        read -p "是否覆盖? (y/n) [n]: " cov
        if [[ "$cov" != "y" ]]; then return; fi
    fi

    echo -e "${INFO} 建议设置较长的封禁时间。"
    
    while true; do
        read -p "判定周期 (findtime) [1d]: " jfind
        jfind=${jfind:-1d}
        validate_time "$jfind" && break
        echo -e "${ERR} 格式错误！"
    done
    
    while true; do
        read -p "触发次数 (maxretry) [5]: " jretry
        jretry=${jretry:-5}
        [[ "$jretry" =~ ^[0-9]+$ ]] && break
        echo -e "${ERR} 必须是数字！"
    done
    
    while true; do
        read -p "封禁时长 (bantime)  [1w]: " jban
        jban=${jban:-1w}
        validate_time "$jban" && break
        echo -e "${ERR} 格式错误！"
    done
    
    cat > "$tfile" <<EOF || { echo -e "${ERR} 配置写入失败"; return 1; }
[recidive]
enabled = true
logpath = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime = ${jban}
findtime = ${jfind}
maxretry = ${jretry}
EOF
    echo -e "${OK} 已写入 Recidive 配置: ${YELLOW}${tfile}${PLAIN}"
    restart_f2b
    read -n 1 -s -r -p "按任意键继续..."
}

# 新增：防火墙后端切换
switch_firewall() {
    clear
    local cur=$(get_conf "banaction")
    local cur_all=$(get_conf "banaction_allports")
    echo -e "${BLUE}=== 防火墙联动后端 (Banaction) 设置 ===${PLAIN}"
    echo -e "当前后端: ${GREEN}${cur:-iptables-multiport}${PLAIN}"
    echo -e "全端口后端: ${GREEN}${cur_all:-未设置}${PLAIN}"
    echo -e "---------------------------------------------------"
    echo -e "  1. iptables-multiport (经典/通用 - 默认)"
    echo -e "  2. nftables-multiport (Debian10+/CentOS8+ 推荐)"
    echo -e "  3. ufw (Ubuntu 简单防火墙)"
    echo -e "  4. firewalld (CentOS/RHEL)"
    echo -e "  5. ${BLUE}自动检测推荐${PLAIN}"
    echo -e "  0. 返回"
    
    read -p "请选择: " sel
    local new_act=""
    local new_all=""
    case "$sel" in
        1) new_act="iptables-multiport"; new_all="iptables-allports" ;;
        2) new_act="nftables-multiport"; new_all="nftables-allports" ;;
        3) new_act="ufw"; new_all="ufw" ;;
        4) new_act="firewalld"; new_all="firewalld" ;;
        5) new_act=$(detect_firewall); new_all=$(detect_firewall_allports) ;;
        0) return ;;
        *) echo -e "${ERR} 输入无效"; sleep 1; return ;;
    esac
    
    if [ -n "$new_act" ]; then
        if set_conf "banaction" "$new_act" && set_conf "banaction_allports" "$new_all"; then
            echo -e "${OK} 已设置为: ${new_act} (全端口: ${new_all})"
            restart_f2b
        else
            echo -e "${ERR} 配置更新失败"
        fi
    fi
    read -n 1 -s -r -p "按任意键继续..."
}

# 新增：端口扫描防护模板 (Portscan from Syslog)
add_portscan_jail() {
    clear
    echo -e "${BLUE}=== 新增: 端口扫描防护 (Portscan/Syslog) ===${PLAIN}"
    echo -e "原理: 分析系统日志 (/var/log/syslog|messages) 中的防火墙拒绝记录。"
    echo -e "要求: 你的防火墙 (iptables/ufw Log) 必须开启日志记录，否则无效。"
    echo -e "---------------------------------------------------"

    local logpath=""
    if [ -f /var/log/syslog ]; then
        logpath="/var/log/syslog"
    elif [ -f /var/log/messages ]; then
        logpath="/var/log/messages"
    else
        echo -e "${ERR} 未找到常见系统日志文件 (syslog/messages)。"
        read -p "请输入日志文件绝对路径: " logpath
        [ -z "$logpath" ] && return
        
        if [ ! -f "$logpath" ]; then
            echo -e "${WARN} 文件不存在，但将继续创建配置"
        fi
    fi

    mkdir -p "$JAIL_D_DIR"
    local target="${JAIL_D_DIR}/portscan.local"
    
    if [ -f "$target" ]; then
         echo -e "${WARN} Portscan Jail 已存在。"
         read -p "是否覆盖? (y/n) [n]: " cov
         if [[ "$cov" != "y" ]]; then return; fi
    fi
    
    cat > "$target" <<EOF || { echo -e "${ERR} 配置写入失败"; return 1; }
[portscan]
enabled = true
filter = portscan
logpath = $logpath
maxretry = 2
findtime = 10m
bantime = 24h
EOF

    echo -e "${OK} 已写入配置: ${YELLOW}${target}${PLAIN}"
    restart_f2b
    read -n 1 -s -r -p "按任意键继续..."
}

# 新增：端口级速率限制 (Iptables Hashlimit)
setup_rate_limit() {
    clear
    echo -e "${BLUE}=== 端口级速率限制 (Rate Limit) ===${PLAIN}"
    echo -e "${WARN} ⚠️  警告：直接操作 iptables INPUT 链顶端。"
    echo -e "如果使用 UFW/Firewalld，重启后可能失效，或者产生规则冲突。"
    echo -e "当前仅实现 iptables (hashlimit) 方式，非 Fail2ban 功能。"
    echo -e "---------------------------------------------------"
    
    if ! command -v iptables >/dev/null; then
        echo -e "${ERR} 未找到 iptables 命令。"
        read -n 1 -s -r -p "按任意键返回..."
        return
    fi
    
    while true; do
        read -p "请输入限制端口 [22]: " port
        port=${port:-22}
        validate_port "$port" && break
        echo -e "${ERR} 端口必须是 1-65535 之间的数字！"
    done
    
    while true; do
        read -p "每分钟允许新建连接数 [30]: " limit_rate
        limit_rate=${limit_rate:-30}
        [[ "$limit_rate" =~ ^[0-9]+$ ]] && break
        echo -e "${ERR} 必须是数字！"
    done
    
    while true; do
        read -p "允许突发连接数 (Burst) [60]: " limit_burst
        limit_burst=${limit_burst:-60}
        [[ "$limit_burst" =~ ^[0-9]+$ ]] && break
        echo -e "${ERR} 必须是数字！"
    done
    
    echo -e "\n即将对端口 ${GREEN}${port}${PLAIN} 执行:"
    echo -e "1. 允许: ${limit_rate}/min (Burst: ${limit_burst})"
    echo -e "2. 拒绝: 超过部分直接 DROP"
    read -p "确认执行? (y/n): " confirm
    [[ "$confirm" != "y" ]] && return

    echo -e "${INFO} 正在插入规则..."
    local name="rl_${port}"
    
    # 清理旧规则
    iptables -D INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW -j DROP 2>/dev/null
    iptables -D INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW \
      -m hashlimit --hashlimit "${limit_rate}/min" --hashlimit-burst "$limit_burst" --hashlimit-mode srcip \
      --hashlimit-name "$name" -j ACCEPT 2>/dev/null

    # 插入 Drop
    if iptables -I INPUT 1 -p tcp --dport "$port" -m conntrack --ctstate NEW -j DROP 2>/dev/null; then
        # 插入 Accept
        if iptables -I INPUT 1 -p tcp --dport "$port" -m conntrack --ctstate NEW \
          -m hashlimit --hashlimit "${limit_rate}/min" --hashlimit-burst "$limit_burst" --hashlimit-mode srcip \
          --hashlimit-name "$name" -j ACCEPT 2>/dev/null; then
            
            echo -e "${OK} 规则已添加。"
            echo -e "${WARN} 请注意：这些规则未持久化保存。重启后会丢失。"
            echo -e "       推荐使用 iptables-save > /etc/iptables/rules.v4 或相应命令保存。"
        else
            echo -e "${ERR} ACCEPT 规则添加失败"
            # 回滚 DROP 规则
            iptables -D INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW -j DROP 2>/dev/null
        fi
    else
        echo -e "${ERR} 规则添加失败，请检查权限或 iptables 状态。"
    fi
    read -n 1 -s -r -p "按任意键继续..."
}

# 核心：Jail 维护中心
manage_jails() {
    while true; do
        clear
        local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | awk -F':' '{print $2}' | tr -d ',' | sed 's/^[ \t]*//')
        local jail_array=($jails)
        
        echo -e "${BLUE}===================================================${PLAIN}"
        echo -e "${BLUE}         Jail 维护中心 (Maintenance Center)       ${PLAIN}"
        echo -e "${BLUE}===================================================${PLAIN}"
        echo -e "  序号  服务名称 (Jail Name)       当前封禁 (Banned)"
        echo -e "---------------------------------------------------"
        
        if [ ${#jail_array[@]} -eq 0 ]; then
            echo -e "  (无活跃的 Jail)"
        else
            for i in "${!jail_array[@]}"; do
                local jname=${jail_array[$i]}
                local jcount=$(fail2ban-client status "$jname" 2>/dev/null | grep "Currently banned" | grep -o "[0-9]*")
                printf "  %-4d  ${YELLOW}%-25s${PLAIN}  ${RED}%s${PLAIN}\n" "$((i+1))" "${jname}" "${jcount:-0}"
            done
        fi
        echo -e "---------------------------------------------------"
        echo -e "  u. [IP 解封] - 输入序号解封特定 Jail 下的 IP"
        echo -e "  d. [删除服务] - 永久移除并清理自定义 Jail 配置"
        echo -e "  0. 返回主菜单"
        echo -e ""
        read -p "请选择操作: " op
        
        case "$op" in
            u|U)
                read -p "请输入要管理的服务序号: " idx
                if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -le "${#jail_array[@]}" ] && [ "$idx" -gt 0 ]; then
                    local target=${jail_array[$((idx-1))]}
                    local blist=$(fail2ban-client status "$target" 2>/dev/null | grep "Banned IP list" | awk -F':' '{print $2}' | sed 's/^[ \t]*//')
                    echo -e "\n${BLUE}Jail [${target}] 黑名单:${PLAIN}\n${RED}${blist:-无}${PLAIN}"
                    
                    read -p "输入要解封的 IP (留空取消): " tip
                    if [ -n "$tip" ]; then
                        if validate_ip "$tip"; then
                            if fail2ban-client set "$target" unbanip "$tip" 2>/dev/null; then
                                echo -e "${OK} IP ${tip} 已解封"
                            else
                                echo -e "${ERR} 解封失败（IP 可能不在黑名单中）"
                            fi
                        else
                            echo -e "${ERR} IP 格式无效！"
                        fi
                    fi
                    read -n 1 -s -r -p "按任意键继续..."
                else
                    echo -e "${ERR} 序号无效"
                    sleep 1
                fi ;;
            d|D)
                read -p "请输入要删除的服务序号: " idx
                if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -le "${#jail_array[@]}" ] && [ "$idx" -gt 0 ]; then
                    local target=${jail_array[$((idx-1))]}
                    
                    if [ "$target" == "sshd" ]; then
                        echo -e "${WARN} 禁止删除核心 sshd 防护。"
                        sleep 2
                        continue
                    fi
                    
                    read -p "确认永久删除 ${target} 的配置? (y/n): " confirm
                    if [[ "$confirm" == "y" ]]; then
                        local tfile="${JAIL_D_DIR}/${target}.local"
                        if [ -f "$tfile" ]; then
                            rm -f "$tfile" && echo -e "${OK} 已删除: $tfile" || echo -e "${ERR} 删除失败"
                        else
                            echo -e "${WARN} 配置文件未找到 (可能在 jail.local 中)。"
                        fi
                        restart_f2b
                    fi
                else
                    echo -e "${ERR} 序号无效"
                    sleep 1
                fi ;;
            0) return ;;
            *) echo -e "${ERR} 无效选项"; sleep 1 ;;
        esac
    done
}

add_whitelist() {
    clear
    local cur=$(get_conf "ignoreip")
    echo -e "${BLUE}--- 白名单管理 ---${PLAIN}"
    echo -e "当前: ${YELLOW}${cur:-无}${PLAIN}"
    echo -e ""

    local cip=$(echo $SSH_CLIENT | awk '{print $1}')
    read -p "输入 IP (回车自动添加本机 ${cip:-未知}): " iip
    iip=${iip:-$cip}
    
    if [ -z "$iip" ]; then
        echo -e "${WARN} 未输入 IP"
        read -n 1 -s -r -p "按任意键继续..."
        return
    fi
    
    # 增强 IP 验证
    if validate_ip "$iip"; then
        # 使用 -w 进行全词匹配，避免 1.2.3.4 匹配到 1.2.3.45
        if echo "$cur" | grep -Fqw "$iip"; then
            echo -e "${WARN} IP ${iip} 已在白名单中"
        else
            local new_list=$(echo "${cur} ${iip}" | sed 's/^[ \t]*//' | sed 's/[ \t]*$//')
            if set_conf "ignoreip" "$new_list"; then
                restart_f2b
            else
                echo -e "${ERR} 白名单添加失败"
            fi
        fi
    else
        echo -e "${ERR} IP 格式无效！"
        echo -e "${INFO} 支持格式: 192.168.1.1, 192.168.1.0/24, ::1, 2001:db8::/32"
    fi
    
    read -n 1 -s -r -p "按任意键继续..."
}

view_logs() {
    clear
    echo -e "${BLUE}=== Fail2ban 历史日志 ===${PLAIN}"
    echo -e ""
    
    if [ -f /var/log/fail2ban.log ]; then
        # 优化：只读取最后 1000 行，再筛选
        tail -n 1000 /var/log/fail2ban.log | grep -E "(Ban|Unban)" | tail -n 30 | \
        awk '{
            gsub(/Unban/,"\033[32m&\033[0m")
            gsub(/Ban/,"\033[31m&\033[0m")
            if($4~/^\[.*\]:$/) $4=sprintf("%9s",$4)
            print
        }'
    else
        journalctl -u fail2ban --no-pager -n 30 2>/dev/null | grep -E "(Ban|Unban)" || \
        echo -e "${WARN} 未找到日志文件"
    fi
    
    echo -e ""
    read -n 1 -s -r -p "按任意键退出..."
}

menu_exponential() {
    while true; do
        clear
        local inc=$(get_conf "bantime.increment")
        local fac=$(get_conf "bantime.factor")
        local max=$(get_conf "bantime.maxtime")
        
        if [ "$inc" == "true" ]; then
            S_INC="${GREEN}ON${PLAIN}"
        else
            S_INC="${RED}OFF${PLAIN}"
        fi
        
        echo -e "${BLUE}=== 指数封禁设置 ===${PLAIN}"
        echo -e "  1. 开关 [${S_INC}]"
        echo -e "  2. 系数 [${YELLOW}${fac:-1}${PLAIN}]"
        echo -e "  3. 上限 [${YELLOW}${max:-30d}${PLAIN}]"
        echo -e "  0. 返回"
        echo -e ""
        read -p "选择: " sc
        
        case "$sc" in
            1) 
                if [ "$inc" == "true" ]; then
                    ns="false"
                else
                    ns="true"
                fi
                if set_conf "bantime.increment" "$ns"; then
                    restart_f2b
                fi
                ;;
            2) change_param "增长系数" "bantime.factor" "int" ;;
            3) change_param "封禁上限" "bantime.maxtime" "time" ;;
            0) return ;;
            *) echo -e "${ERR} 无效选项"; sleep 1 ;;
        esac
    done
}

change_param() {
    local n=$1
    local k=$2
    local t=$3
    local cur=$(get_conf "$k")
    
    echo -e "\n修改: ${n}"
    echo -e "当前: ${GREEN}${cur:-未设置}${PLAIN}"
    
    while true; do
        read -p "新值 (留空取消): " nv
        [ -z "$nv" ] && return
        
        if [[ "$t" == "time" ]]; then
            if validate_time "$nv"; then
                break
            else
                echo -e "${RED}格式错误！示例: 10m, 1h, 1d, 1w${PLAIN}"
            fi
        elif [[ "$t" == "int" ]]; then
            if [[ "$nv" =~ ^[0-9]+$ ]]; then
                break
            else
                echo -e "${RED}必须是数字！${PLAIN}"
            fi
        else
            break
        fi
    done
    
    if set_conf "$k" "$nv"; then
        restart_f2b
    else
        echo -e "${ERR} 参数更新失败"
    fi
}

# ------------------------------------------------------------------
# 五、主循环 (Main Menu)
# ------------------------------------------------------------------

check_root

while true; do
    clear
    
    # 检查是否已安装
    if ! command -v fail2ban-client &>/dev/null; then
        echo -e "${YELLOW}Fail2ban 未安装！${PLAIN}"
        echo -e "  1. 立即安装 (支持 Debian/CentOS 全系)"
        echo -e "  0. 退出"
        read -p "请选择: " ic
        
        if [ "$ic" == "1" ]; then
            install_f2b
        else
            exit 0
        fi
        continue
    fi
    
    # 读取当前配置
    VAL_MAX=$(get_conf "maxretry")
    VAL_BAN=$(get_conf "bantime")
    VAL_FIND=$(get_conf "findtime")
    
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "${BLUE}         Fail2ban 防火墙管理 (F2B Panel)          ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "  状态: $(get_status)"
    echo -e "---------------------------------------------------"
    echo -e "  1. 修改 最大重试次数 [${YELLOW}${VAL_MAX:-5}${PLAIN}]"
    echo -e "  2. 修改 初始封禁时长 [${YELLOW}${VAL_BAN:-1h}${PLAIN}]"
    echo -e "  3. 修改 监测时间窗口 [${YELLOW}${VAL_FIND:-10m}${PLAIN}]"
    echo -e "---------------------------------------------------"
    echo -e "  4. ${GREEN}Jail 维护中心${PLAIN} (List/Unban/Delete) ->"
    echo -e "  5. ${GREEN}添加白名单${PLAIN}   (Whitelist)"
    echo -e "  6. 查看封禁日志 (Logs)"
    echo -e "  7. ${YELLOW}指数封禁设置${PLAIN} (Advanced) ->"
    echo -e "---------------------------------------------------"
    echo -e "  8. 开启/停止 Fail2ban 服务 (On/Off)"
    echo -e "  9. ${PURPLE}新增 服务检测${PLAIN} (Add Jail) (实验功能)"
    echo -e "  10. ${PURPLE}新增 端口扫描防护${PLAIN} (Recidive Jail) (实验功能)"
    echo -e "  11. ${YELLOW}防火墙后端 (IPtables/NFTables)${PLAIN}"
    echo -e "  12. ${PURPLE}新增 端口扫描模板${PLAIN} (Scan Log) (实验功能)"
    echo -e "  13. ${YELLOW}设置 端口速率限制${PLAIN} (Rate Limit) (实验功能)"
    echo -e "  14. ${GREEN}查看 底层防火墙拦截状态${PLAIN} (Firewall Check)"
    echo -e "  0. 退出"
    
    read -p "请输入选项 [0-14]: " choice
    
    case "$choice" in
        1) change_param "最大重试次数" "maxretry" "int" ;;
        2) change_param "初始封禁时长" "bantime"  "time" ;;
        3) change_param "监测时间窗口" "findtime" "time" ;;
        4) manage_jails ;;
        5) add_whitelist ;;
        6) view_logs ;;
        7) menu_exponential ;;
        8) 
            if svc_active fail2ban; then
                echo -e "${INFO} 正在停止 Fail2ban..."
                if svc_stop fail2ban && svc_disable fail2ban; then
                    echo -e "${OK} ${RED}已停止${PLAIN}"
                else
                    echo -e "${ERR} 停止失败"
                fi
            else
                echo -e "${INFO} 正在启动 Fail2ban..."
                if svc_enable fail2ban && svc_start fail2ban; then
                    echo -e "${OK} ${GREEN}已启动${PLAIN}"
                else
                    echo -e "${ERR} 启动失败"
                fi
            fi
            read -n 1 -s -r -p "按键继续..."
            ;;
        9) add_custom_jail ;;
        10) add_recidive_jail ;;
        11) switch_firewall ;;
        12) add_portscan_jail ;;
        13) setup_rate_limit ;;
        14) check_firewall_rules ;;
        0) clear; echo -e "${GREEN}感谢使用！${PLAIN}"; exit 0 ;;
        *) echo -e "${ERR} 无效选项"; sleep 1 ;;
    esac
done