# neoxy

按 SNI / 协议特征分流 TLS 流量的代理，用 Rust 编写并新增 HTTP/3 (QUIC)。

## 一键安装（安装到 /opt/neoxy）

```bash
cd neoxy
sudo bash install.sh
# 或跳过提问：
sudo DOMAIN=abc.example.com EMAIL=me@example.com bash install.sh
```

| 路径 | 说明 |
|---|---|
| `/opt/neoxy/neoxy` | 程序（同时链接到 `/usr/local/bin/neoxy`） |
| `/opt/neoxy/config.yaml` | 配置文件 |
| `/opt/neoxy/acme/` | 自动证书缓存 |
| `/opt/neoxy/src/` | 源码备份（更新时用） |
| `/etc/systemd/system/neoxy.service` | systemd 服务 |

常用命令：

```bash
systemctl restart neoxy
journalctl -u neoxy -f
sudo bash /opt/neoxy/src/install.sh   # 更新：重新编译并重启
sudo bash install.sh uninstall        # 卸载（保留配置）
sudo bash install.sh uninstall --purge
```

## 功能

| 功能 | 状态 |
|---|---|
| `listen` / `redirecthttps` / `fallback` | ✅ |
| `inboundbuffersize` / `outboundbuffersize` | ✅ |
| SNI 分流、`tlsoffloading` | ✅ |
| `cert` / `key`、`alpn`、`protocols` | ✅ |
| `managedcert` 自动证书（Let's Encrypt, TLS-ALPN-01，需监听 443） | ✅ |
| 解开 TLS 后嗅探 http / h2 / trojan / 其他 | ✅ |
| `http.paths`（前缀、`trimprefix`、`"*"`）、`http2` | ✅ |
| `proxyPass`：`host:port` / `unix:` / `;proxyProtocol`(v1) / `h2c://`，含 WebSocket | ✅ |
| `fileServer`（index.html、Range、304） | ✅ |
| HTTP/3 | ✅ `http3: true` |

## HTTP/3

- 同一端口同时监听 TCP（TLS）和 UDP（QUIC），仅对 `tlsoffloading: true` 的 vhost 生效。
- h3 请求与 h2 共用路由规则：有 `http2` 就按 `http2` 匹配，否则取 `http.paths` 中的 `"*"`，再否则用 `http.handler`。
- TCP 侧的 HTTP 响应自动带 `Alt-Svc: h3=":443"; ma=86400`。
- 记得放行 **UDP 443**（含云厂商安全组）。

## 额外配置项

`http3`、`acmeemail`、`acmecache`（默认 `/opt/neoxy/acme`）、`acmestaging`。

## 已知差异

- `keytype`：只签发 ECDSA P-256，其他取值被忽略。
- 证书只做精确域名匹配（不支持通配符），证书文件变更后需重启。
- `fileServer` 无目录列表。
