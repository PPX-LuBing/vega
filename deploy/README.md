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

装完按提示走：`vega-panel doctor` → `vega-panel apply` → `systemctl enable --now ...`。

## 单元文件

`systemd/` 下的文件是**模板**，安装时用 `sed` 把 `__DOMAIN__` / `__SUB_PORT__` /
`__SUB_BASE__` 换成实际值。手改也可以，改完记得 `systemctl daemon-reload`。

| 单元 | 作用 | 是否必需 |
|---|---|---|
| `vega.service` | 内核 | 必需 |
| `vega-sub.service` | HTTPS 订阅 + ACME 证书 | 用订阅就需要 |
| `vega-cert-check.timer` | 每天检查证书并续期 | 建议启用 |
| `vega-enforce.service` | 用量采集 + 配额执行 | 可选 |

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
