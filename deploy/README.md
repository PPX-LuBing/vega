# 部署资产

和 `panel/`、`third_party/` 一样，这里是 **Vega 自有**的内容，不涉及上游 sing-box。

## 装出来的布局

```
/opt/vega/bin/vega            内核（sing-box + nowhere）
/opt/vega/bin/vega-panel      面板 / 订阅服务 / CLI
/opt/vega/bin/sb-stats        按用户统计
/opt/vega/etc/config.json     内核配置（由 vega-panel apply 生成，安装脚本不写）
/var/lib/vega/panel.db        面板数据库（0700）
/var/lib/vega/certs/          ACME 证书
/var/lib/vega/acme/           ACME 账户缓存
/etc/systemd/system/vega*.{service,timer}
```

## 用法

```sh
sh deploy/install.sh ./vega ./vega-panel ./sb-stats \
   --domain sub.example.com --sub-port 8443
```

- `--domain` **必填**：订阅服务要用它签 ACME 证书、生成订阅链接
- 脚本只铺文件和单元，**不启动、不启用任何服务**（避免装完自动起一个没配好的内核）
- 已存在的 `config.json` / `panel.db` 不会被覆盖
- `DESTDIR=/tmp/stage` 可只铺到临时目录，打包或跑测试用

装完按提示走：`vega-panel doctor` → `vega-panel apply` → 启用服务。

```sh
systemctl enable --now vega vega-sub vega-cert-check.timer vega-enforce
```

⚠️ **`vega-enforce` 不能漏**：它是唯一持续采集流量的组件，不启用则面板
流量统计恒为 0（只有手动 `vega-panel collect` 才有数据）。

也可以一步到位：`sh deploy/install.sh ... --enable`（装完自动 apply + 启用全部服务）。

## 单元文件

`systemd/` 下的文件是**模板**，安装时用 `sed` 把 `__DOMAIN__` / `__SUB_PORT__` /
`__SUB_BASE__` 换成实际值。手改也可以，改完记得 `systemctl daemon-reload`。

| 单元 | 作用 | 是否必需 |
|---|---|---|
| `vega.service` | 内核 | 必需 |
| `vega-sub.service` | HTTPS 订阅 + ACME 证书 | 用订阅就需要 |
| `vega-cert-check.timer` | 每天检查证书并续期 | 建议启用 |
| `vega-enforce.service` | 用量采集 + 配额执行 | 可选 |

## `camo/`：REALITY 的伪装站

`camo/` 是给 REALITY 当 `dest` 用的极简 HTTPS 静态站，**不是必需组件** ——
只有想让 REALITY 的回落目标更像真网站时才装（目前只有 CN2 那台用）。

```
/opt/camo/serve.py            Python 标准库实现，零依赖
/opt/camo/site/               静态站点根目录（自己放，不随仓库分发）
/etc/systemd/system/camo.service
```

REALITY 对 `dest` 有两条硬性要求，**换站点时必须先验，否则节点直接连不上**：

1. **只允许 TLS 1.3**（`minimum_version = maximum_version = TLSv1_3`）
2. **支持 X25519**（`set_ecdh_curve("X25519")`）

### ⚠️ 2026-11-27 修掉的致命 bug（`serve.py` 必须用本仓库这份）

旧版把**监听 socket** 直接包上 TLS：

```python
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)   # 错的
```

这样握手发生在 `accept()` 内部、在单线程主循环里同步执行。**只要有人建立一条
TCP 连接但一个字节都不发**（端口扫描器、探针、`curl` 超时前的半开连接都算），
`accept()` 就停在握手上，整个进程不再接受任何新连接。

而 REALITY 每次握手都要先 `DialContext` 到 dest 才能比对 ClientHello：

```
ERROR inbound/vless[us2-reality]: TLS handshake: REALITY: failed to dial dest:
      dial tcp 127.0.0.1:9443: i/o timeout
```

→ 表现成「**节点连不上**」，极易误判成 SNI 配错。当时从 4 个外部探测点看
443 端口是 `Connection reset by peer`，而 8443 订阅正常，就是 dest 卡死。

修法：**监听 socket 保持明文，`wrap_socket` 挪到 `finish_request`（工作线程）里**，
同时加 `CONN_TIMEOUT=10` 和并发上限 `MAX_CONNS=64`（`MemoryMax=64M`）。

> **教训**：伪装站是 REALITY 的**数据面依赖**，不是装饰。它挂掉的症状是
> 「协议连不上」，排查时会一路往 SNI / 密钥 / 防火墙方向走，全是岔路。
> 先看内核日志有没有 `failed to dial dest`，两秒定位。

### 装法

```sh
install -D -m 644 deploy/camo/serve.py /opt/camo/serve.py
install -D -m 644 deploy/camo/camo.service /etc/systemd/system/camo.service
systemctl daemon-reload && systemctl enable --now camo
```

`serve.py` 里 `ROOT` / `CERT` / `KEY` 三个路径写死了，换机器要改。

## 环境变量前缀为什么还叫 `SBX_PANEL_*`

历史遗留（项目早期叫 sbx）。**线上单元文件里就是这些名字**，改名要同步改
所有机器的 systemd 单元，收益为零、风险不小，所以保持不变——只是命名不直观，
看到 `SBX_` 就理解成「Vega 面板的」即可。

## 测试

```sh
sh deploy/install_test.sh
```

会检查：文件路径、状态目录权限（0700）、占位符是否全部替换、是否还残留
`/usr/local` 旧路径、已有数据是否被覆盖、以及**没有启用任何服务**。
