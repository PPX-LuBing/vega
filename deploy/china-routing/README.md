# 中国大陆侧 AI / Google 分流清单

这份清单解决一件事：**香港机房那台机器的 AI 与 Google 流量走台湾家宽落地，
其余流量走香港直出。**

- 出站名：`chain-tw`（shadowsocks → `tw.luckybyte.de5.net:50360`）
- 生效方式：`vega-panel setting set extra_config` + `apply`（面板会把它**追加**进
  已生成的 `config.json`，`route.final` 仍是 `direct`）
- 本目录只放**清单**和**生成脚本**，不放服务器密码（见「密码怎么来」）

## 为什么需要它

### 1. AI 服务的地区限制

ChatGPT / Claude / Gemini 等对香港 IP 有额外风控或直接拒服务。走台湾家宽
（HiNet 动态 IP，AS3462）表现接近真实住宅用户。

### 2. 香港那台被「送中」

实测（2026-11-28）：

| 域名 | 香港解析 | 归属 |
|---|---|---|
| `www.gstatic.com` | `203.208.40.2` | **北京 AS24424（Google 中国专用段）** |
| `fonts.gstatic.com` | `203.208.40.2` | 同上 |
| `redirector.gvt1.com` | `203.208.40.1` | 同上 |

台湾同一域名解析到 `142.251.150.120`（正常国际段），`google.com` 也不跳 `.com.hk`。

> 注意：**只有 `gstatic` / `gvt1` / `gvt2` 被送中**，`www.google.com` / `mail` /
> `play` / `chromewebstore` 在香港解析是正常的。整条 Google 系一起走台湾是
> 为了统一维护 + 拿到真正国际版搜索结果，不是因为它们全都坏了。

## 清单

| 文件 | 内容 |
|---|---|
| `ai-domains.txt` | 30 个非 Google 的 AI 站点 |
| `google-domains.txt` | 38 个 Google 系域名 |
| `gen-config.sh` | 读上面两个清单 + 密码，生成 `extra_config` JSON |
| `gen-config_test.sh` | 自测（不需要网络/root）：`sh gen-config_test.sh` |

两个清单合计 **68 个裸域名**，脚本会为每个自动展开成「裸域名 + `.裸域名`」两条，
生成 **136 条 `domain_suffix`**。生成结果已与线上 `136 条` 逐条比对一致。

### 为什么要同时写 `a.com` 和 `.a.com`

`sagernet/sing` 的 `domain_suffix` 是按**标签边界**匹配，语义已验证：

```
domain_suffix = ["google.com", ".google.com"]
  www.google.com          → 命中 ✅
  google.com              → 命中 ✅（裸域名那条）
  notgoogle.com           → 不命中 ✅
  mygoogle.com.evil.net   → 不命中 ✅
```

不带点的那条匹配「自身 + 子域」，带点的那条只匹配子域。两条都写是为了兼容
两种习惯写法、并和面板自带规则保持一致。

**绝对不要**写成 `domain_keyword`——那会按子串匹配，`notgoogle.com` 也会被导走。

### 为什么保留了 `googleapis.com` 全量通配

`googleapis.com` 一条就能覆盖全部 Google API（Gemini / Cloud / Drive / oauth /
fcm / youtube-data ...），**这是有意的**——需求就是「Google 系全走台湾」。

代价实测过（2026-11-28，5MB 下载）：

| 路径 | 速度 |
|---|---|
| 经台湾 | **7.1 MB/s** |
| 香港直连 | 18.7 MB/s |

台湾带宽约为香港的 38%，日常 API 调用、搜索、Gmail 完全够用。
但如果将来有人要把大型文件同步（Drive 大文件、云盘）也压过去，要盯着家宽上行。

### 为什么唯独把 YouTube 视频流排除在外

台湾落地是 **HiNet 家宽、512MB 内存**，不是机房。实测容量：

```
协商速率 10000 Mb/s（实际受家宽套餐限制，实测约 7MB/s）
内存 512MB，可用 430MB
```

视频流是**长连接大流量**，和 API 调用完全不同的量级，所以刻意不放：

| 走台湾 | 保持香港直连 |
|---|---|
| Google 搜索 / Gmail / API / Play / 应用商店 / gstatic CDN | `youtube.com`、`googlevideo.com`、`ytimg.com` |

YouTube 在香港直连是通的，没必要给家宽加压。要改的话，往
`google-domains.txt` 里加对应域名重跑即可，但先看上面那张带宽表。

## 用法

### 1. 在目标机上准备密码文件

密码是 `SS2022 服务端PSK:用户PSK` 格式。**不要提交进仓库**。

```sh
umask 077
cat > /root/vega-tw-landing.env <<'EOF'
TW_SERVER=tw.luckybyte.de5.net
TW_PORT=50360
TW_METHOD=2022-blake3-aes-128-gcm
TW_PASSWORD=<服务端PSK>:<用户PSK>
EOF
```

### 2. 生成配置

```sh
sh deploy/china-routing/gen-config.sh /root/vega-tw-landing.env > /root/ai-tw.json
```

脚本会校验：清单文件存在、密码非空、生成的 JSON 合法。

### 3. 注入并生效

```sh
. /root/vega-env.sh
/opt/vega/bin/vega-panel setting set extra_config "$(cat /root/ai-tw.json)"
/opt/vega/bin/vega-panel apply
systemctl is-active vega        # 必须是 active
```

### 4. 验证（**别只看 HTTP 200**）

HTTP 200 只能证明「能访问」，证明不了「走了台湾」。用连接峰值法：

```sh
# 台湾落地 IP 会变，先解析
TW=$(getent ahosts tw.luckybyte.de5.net | awk '{print $1; exit}')

# 一边高频采样到台湾的连接数，一边发起请求
( while :; do ss -tn | grep -c "$TW:50360"; sleep 0.03; done ) &
SAMPLE=$!
curl -s -o /dev/null --socks5-hostname 127.0.0.1:<你的入站端口> https://www.google.com/
kill $SAMPLE
```

峰值 > 0 才算真走了台湾。**不要用「当前连接数」判断**——shadowsocks 用完立刻
`FIN-WAIT-1` 关闭，直接 `ss` 数永远是 0，会误判成分流没生效（这个坑踩过）。

## 维护

### 台湾落地换了密码 / 端口

改 `/root/vega-tw-landing.env`，重新跑生成 + `apply`。不用动清单。

### 要加/删域名

直接编辑 `*.txt`（一行一个，`#` 开头是注释），重新生成 + `apply`。

### 回滚

```sh
/opt/vega/bin/vega-panel setting set extra_config "$(cat /root/ai-tw.bak-<时间戳>.json)"
/opt/vega/bin/vega-panel apply
```

## 已知风险

1. **台湾是单点。** 它挂了，AI + Google 全断。
   没有加自动故障转移是有意的：`urltest` 会把 `direct` 和 `chain-tw` 一起测速，
   而香港直连 Google 更快，规则会直接失效——比断了更隐蔽。
2. **台湾 IP 是动态的。** 配置里写域名，跟 DDNS 走。DDNS 挂了分流也会失效。
3. **台湾家宽不适合跑视频。** 别往里加 `googlevideo.com` 之类的域名。
