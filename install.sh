#!/usr/bin/env bash
# neoxy 一键安装脚本（安装到 /opt/neoxy）
# 用法（在项目目录内，以 root 运行）：
#   bash install.sh                      安装 / 更新（重新编译并重启）
#   bash install.sh uninstall            卸载程序（保留 /opt/neoxy 下的配置和证书）
#   bash install.sh uninstall --purge    卸载并删除 /opt/neoxy 全部内容
#
# 可用环境变量跳过交互：  DOMAIN=abc.example.com EMAIL=me@example.com bash install.sh
set -euo pipefail

NAME=neoxy
LEGACY=tls-shunt-proxy
APP_DIR=/opt/$NAME
BIN=$APP_DIR/$NAME
LINK=/usr/local/bin/$NAME
CONF=$APP_DIR/config.yaml
ACME_DIR=$APP_DIR/acme
SERVICE=/etc/systemd/system/$NAME.service
WEBROOT=/var/www/html
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SWAPFILE=/swapfile.neoxy.tmp
TOOL_DIR=$APP_DIR/.rust      # 脚本自带的 Rust 工具链（编译后默认删除）
BUILD_DIR=$APP_DIR/.build    # 编译产物目录（编译后删除）
SRC_COPY=$APP_DIR/src        # 源码备份，方便以后更新
# KEEP_RUST=1 可保留工具链，下次更新不用重新下载

c_g=$'\e[32m'; c_y=$'\e[33m'; c_r=$'\e[31m'; c_0=$'\e[0m'
info() { echo "${c_g}[+]${c_0} $*"; }
warn() { echo "${c_y}[!]${c_0} $*"; }
die()  { echo "${c_r}[x]${c_0} $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo bash install.sh）"
command -v systemctl >/dev/null || die "需要 systemd"

# ───────────────────────── 卸载 ─────────────────────────
if [ "${1:-}" = "uninstall" ]; then
  info "停止并移除服务"
  systemctl disable --now $NAME 2>/dev/null || true
  rm -f "$SERVICE" "$LINK"
  systemctl daemon-reload
  if [ "${2:-}" = "--purge" ]; then
    rm -rf "$APP_DIR"
    userdel $NAME 2>/dev/null || true
    info "已删除 $APP_DIR 与运行用户"
  else
    rm -f "$BIN"
    warn "配置与证书缓存保留在 $APP_DIR（加 --purge 可全部删除）"
  fi
  info "卸载完成"
  exit 0
fi

[ -f "$SRC_DIR/Cargo.toml" ] || die "请把本脚本放在项目目录（含 Cargo.toml）里运行"
if [ ! -f "$SRC_DIR/src/main.rs" ]; then
  if [ -f "$SRC_DIR/main.rs" ]; then
    warn "main.rs 不在 src/ 里，自动移动"
    mkdir -p "$SRC_DIR/src" && mv "$SRC_DIR/main.rs" "$SRC_DIR/src/main.rs"
  else
    die "找不到 src/main.rs，请确认把 main.rs 上传到了 $SRC_DIR/src/ 下"
  fi
fi

# ───────────────────────── 依赖 ─────────────────────────
install_deps() {
  if command -v apt-get >/dev/null; then
    apt-get update -y && apt-get install -y build-essential pkg-config curl ca-certificates
  elif command -v dnf >/dev/null; then
    dnf install -y gcc make pkgconf-pkg-config curl ca-certificates
  elif command -v yum >/dev/null; then
    yum install -y gcc make pkgconfig curl ca-certificates
  else
    die "不支持的发行版，请手动安装 gcc、make、curl 后重试"
  fi
}
if ! command -v cc >/dev/null || ! command -v curl >/dev/null; then
  info "安装编译依赖"
  install_deps
fi

# ───────────────────────── Rust ─────────────────────────
mkdir -p "$APP_DIR"
export RUSTUP_HOME="$TOOL_DIR/rustup" CARGO_HOME="$TOOL_DIR/cargo"
export PATH="$CARGO_HOME/bin:$PATH"
if [ ! -x "$CARGO_HOME/bin/cargo" ]; then
  info "安装 Rust 工具链到 $TOOL_DIR"
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
fi

# ───────────────────────── 小内存临时 swap ─────────────────────────
cleanup() {
  if [ -f "$SWAPFILE" ]; then
    swapoff "$SWAPFILE" 2>/dev/null || true
    rm -f "$SWAPFILE"
  fi
}
trap cleanup EXIT
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
swap_mb=$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo)
if [ "$mem_mb" -lt 1800 ] && [ "$swap_mb" -lt 1024 ]; then
  info "内存 ${mem_mb}MB，创建 1GB 临时 swap 用于编译"
  fallocate -l 1G "$SWAPFILE" 2>/dev/null || dd if=/dev/zero of="$SWAPFILE" bs=1M count=1024 status=none
  chmod 600 "$SWAPFILE"; mkswap "$SWAPFILE" >/dev/null; swapon "$SWAPFILE"
fi

# ───────────────────────── 编译 ─────────────────────────
info "编译中（首次约需 3~10 分钟，请耐心等待）"
CARGO_TARGET_DIR="$BUILD_DIR" cargo build --release --manifest-path "$SRC_DIR/Cargo.toml"

# ───────────────────────── 迁移旧版 tls-shunt-proxy ─────────────────────────
LEGACY_CONF=/etc/$LEGACY/config.yaml
LEGACY_ACME=/var/lib/$LEGACY/acme
MIGRATED=0
if [ -f "/etc/systemd/system/$LEGACY.service" ] || [ -f "$LEGACY_CONF" ]; then
  warn "检测到旧版 $LEGACY，将迁移到 $NAME（旧配置目录不会被删除）"
  systemctl disable --now $LEGACY 2>/dev/null || true
  rm -f "/etc/systemd/system/$LEGACY.service" "/usr/local/bin/$LEGACY"
  systemctl daemon-reload
  mkdir -p "$APP_DIR"
  if [ -f "$LEGACY_CONF" ] && [ ! -f "$CONF" ]; then
    cp "$LEGACY_CONF" "$CONF"
    sed -i "s#/var/lib/$LEGACY#$APP_DIR#g" "$CONF"
    MIGRATED=1
    info "已迁移配置：$LEGACY_CONF → $CONF"
  fi
  if [ -d "$LEGACY_ACME" ] && [ ! -d "$ACME_DIR" ]; then
    cp -a "$LEGACY_ACME" "$ACME_DIR"
    info "已迁移证书缓存：$LEGACY_ACME → $ACME_DIR"
  fi
fi

# ───────────────────────── 安装到 /opt/neoxy ─────────────────────────
systemctl stop $NAME 2>/dev/null || true
id $NAME >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin $NAME
mkdir -p "$APP_DIR" "$ACME_DIR" "$WEBROOT"
install -m755 "$BUILD_DIR/release/$NAME" "$BIN"
ln -sf "$BIN" "$LINK"
info "已安装二进制到 $BIN"

# 清理编译产物 / 工具链
rm -rf "$BUILD_DIR"
if [ "${KEEP_RUST:-0}" != "1" ]; then
  rm -rf "$TOOL_DIR"
  info "已清理编译产物和 Rust 工具链（下次更新会自动重新下载；KEEP_RUST=1 可保留）"
fi
# 备份源码到 /opt/neoxy/src，之后可直接 bash /opt/neoxy/src/install.sh 更新
if [ "$SRC_DIR" != "$SRC_COPY" ]; then
  rm -rf "$SRC_COPY"; mkdir -p "$SRC_COPY"
  for f in Cargo.toml Cargo.lock config.yaml install.sh README.md src; do
    [ -e "$SRC_DIR/$f" ] && cp -a "$SRC_DIR/$f" "$SRC_COPY/"
  done
fi
if [ ! -f "$WEBROOT/index.html" ]; then
  echo '<!doctype html><meta charset="utf-8"><title>Welcome</title><h1>It works.</h1>' > "$WEBROOT/index.html"
fi

# ───────────────────────── 配置 ─────────────────────────
NEW_CONF=0
if [ ! -f "$CONF" ]; then
  NEW_CONF=1
  DOMAIN="${DOMAIN:-}"; EMAIL="${EMAIL:-}"
  if [ -z "$DOMAIN" ] && [ -t 0 ]; then
    read -rp "请输入域名（需已解析到本机，如 abc.example.com；直接回车则使用示例配置）: " DOMAIN
    if [ -n "$DOMAIN" ]; then read -rp "请输入邮箱（用于 Let's Encrypt，可留空）: " EMAIL; fi
  fi
  if [ -n "$DOMAIN" ]; then
    info "生成配置 $CONF"
    cat > "$CONF" <<EOF
listen: 0.0.0.0:443
redirecthttps: 0.0.0.0:80
fallback: 127.0.0.1:8443

# HTTP/3 (QUIC)，需放行 UDP 443
http3: true

acmeemail: ${EMAIL}
acmecache: ${ACME_DIR}
acmestaging: false

vhosts:
  - name: ${DOMAIN}
    tlsoffloading: true
    managedcert: true
    alpn: h2,http/1.1
    protocols: tls12,tls13
    http:
      # paths:
      #   - path: /ws/
      #     handler: proxyPass
      #     args: 127.0.0.1:40000
      handler: fileServer
      args: ${WEBROOT}
    # trojan:
    #   handler: proxyPass
    #   args: 127.0.0.1:4430
    default:
      handler: proxyPass
      args: 127.0.0.1:40001
EOF
  else
    cp "$SRC_DIR/config.yaml" "$CONF"
    sed -i "s#^acmecache:.*#acmecache: ${ACME_DIR}#" "$CONF"
    warn "使用的是示例配置，请编辑 $CONF 后再启动"
  fi
fi
# 迁移来的配置如果没有 acmecache，补上，避免证书缓存写到不可写的位置
if ! grep -q '^acmecache:' "$CONF"; then
  printf '\nacmecache: %s\n' "$ACME_DIR" >> "$CONF"
fi

chown -R $NAME:$NAME "$ACME_DIR"
chown root:$NAME "$APP_DIR" "$CONF"
chmod 750 "$APP_DIR"; chmod 640 "$CONF"

# ───────────────────────── systemd ─────────────────────────
cat > "$SERVICE" <<EOF
[Unit]
Description=neoxy - TLS shunt proxy with HTTP/3
After=network-online.target
Wants=network-online.target

[Service]
User=$NAME
WorkingDirectory=$APP_DIR
ExecStart=$BIN -config $CONF
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable $NAME >/dev/null 2>&1

# ───────────────────────── 防火墙 ─────────────────────────
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  info "ufw 放行 80/tcp 443/tcp 443/udp"
  ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; ufw allow 443/udp >/dev/null
elif command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
  info "firewalld 放行 80/tcp 443/tcp 443/udp"
  firewall-cmd --permanent --add-port=80/tcp --add-port=443/tcp --add-port=443/udp >/dev/null
  firewall-cmd --reload >/dev/null
else
  warn "未检测到启用的 ufw/firewalld；如有云厂商安全组，请手动放行 TCP 80/443 和 UDP 443"
fi

# ───────────────────────── 端口占用检查 ─────────────────────────
if command -v ss >/dev/null; then
  busy=$(ss -ltnp 2>/dev/null | awk '$4 ~ /:(80|443)$/ && $0 !~ /neoxy/ {print $4" "$NF}' || true)
  [ -z "$busy" ] || warn "以下端口已被占用，请先停掉对应程序：
$busy"
fi

# ───────────────────────── 启动 ─────────────────────────
if [ "$NEW_CONF" -eq 1 ] && [ "$MIGRATED" -eq 0 ] && grep -q "example.com" "$CONF"; then
  warn "请编辑 $CONF（改域名、证书、后端地址），然后执行： systemctl restart $NAME"
  exit 0
fi
systemctl restart $NAME
sleep 2
if systemctl is-active --quiet $NAME; then
  info "已启动。查看日志： journalctl -u $NAME -f"
  [ "$SRC_DIR" = "$SRC_COPY" ] || info "源码已备份到 $SRC_COPY，上传目录 $SRC_DIR 现在可以删除"
  { [ -d "$HOME/.cargo" ] || [ -d "$HOME/.rustup" ]; } && warn "发现之前遗留的 ~/.cargo 或 ~/.rustup，不再需要的话可执行：rm -rf ~/.cargo ~/.rustup" || true
  [ -z "${DOMAIN:-}" ] || info "证书签发需要几十秒，稍后访问 https://${DOMAIN}"
else
  warn "启动失败，最近日志："
  journalctl -u $NAME -n 30 --no-pager || true
  exit 1
fi
