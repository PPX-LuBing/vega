#!/bin/sh
# deploy/china-routing 的自测。不需要网络，不需要 root。
#
# 用法: sh deploy/china-routing/gen-config_test.sh
set -eu

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

pass=0
fail=0
ok() { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
no() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

write_env() {
    cat >"$tmp/env" <<'EOF'
TW_SERVER=tw.example.com
TW_PORT=50360
TW_METHOD=2022-blake3-aes-128-gcm
TW_PASSWORD=serverpsk:userpsk
EOF
}

# 用 python 断言 JSON，避免依赖 jq
jassert() {
    python3 - "$@" <<'PY'
import json, sys
path, expr = sys.argv[1], sys.argv[2]
d = json.load(open(path))
ok = eval(expr, {"d": d, "len": len, "set": set})
sys.exit(0 if ok else 1)
PY
}

echo "gen-config.sh"

write_env
sh "$dir/gen-config.sh" "$tmp/env" >"$tmp/out.json" 2>"$tmp/err" || {
    no "生成失败"
    cat "$tmp/err"
    exit 1
}
ok "生成成功"

jassert "$tmp/out.json" 'True' 2>/dev/null && ok "JSON 合法" || no "JSON 合法"

# 出站结构
jassert "$tmp/out.json" 'd["outbounds"][0]["tag"] == "chain-tw"' 2>/dev/null &&
    ok "出站 tag = chain-tw" || no "出站 tag"
jassert "$tmp/out.json" 'd["outbounds"][0]["server_port"] == 50360' 2>/dev/null &&
    ok "端口是数字不是字符串" || no "端口类型"
jassert "$tmp/out.json" 'd["outbounds"][0]["password"] == "serverpsk:userpsk"' 2>/dev/null &&
    ok "密码正确传入" || no "密码"

# 规则结构
jassert "$tmp/out.json" 'd["route"]["rules"][0]["action"] == "route"' 2>/dev/null &&
    ok "action = route" || no "action"
jassert "$tmp/out.json" 'd["route"]["rules"][0]["outbound"] == "chain-tw"' 2>/dev/null &&
    ok "outbound = chain-tw" || no "outbound"

# 条目数量：每个裸域名两条
bare=$(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$dir/ai-domains.txt" "$dir/google-domains.txt" |
    sed -e '/^$/d' | sort -u | wc -l | tr -d ' ')
want=$((bare * 2))
jassert "$tmp/out.json" "len(d['route']['rules'][0]['domain_suffix']) == $want" 2>/dev/null &&
    ok "条目数 = 裸域名 × 2（${bare} × 2 = ${want}）" || no "条目数应为 $want"

# 去重：不应有重复条目
jassert "$tmp/out.json" 'len(d["route"]["rules"][0]["domain_suffix"]) == len(set(d["route"]["rules"][0]["domain_suffix"]))' 2>/dev/null &&
    ok "无重复条目" || no "有重复条目"

# 裸域 + 点前缀成对出现
jassert "$tmp/out.json" 'all(("." + x) in d["route"]["rules"][0]["domain_suffix"] for x in d["route"]["rules"][0]["domain_suffix"] if not x.startswith("."))' 2>/dev/null &&
    ok "每个裸域都有对应的 . 前缀条目" || no "裸域/前缀不成对"

# 生成结果已与线上 136 条逐条比对一致（含顺序）。加一条顺序断言，
# 防止将来重排清单导致 diff 变吵、或误删分组注释所在的条目。
jassert "$tmp/out.json" '[d["route"]["rules"][0]["domain_suffix"][i] for i in (0, 60, 124, 134)] == ["openai.com", "generativelanguage.googleapis.com", "google.com", "google.org"]' 2>/dev/null &&
    ok "条目顺序与生产一致（抽样 4 点）" || no "条目顺序变了"

# 关键域名必须在
for want_dom in generativelanguage.googleapis.com gstatic.com chatgpt.com gemini.google.com; do
    jassert "$tmp/out.json" "'$want_dom' in d['route']['rules'][0]['domain_suffix']" 2>/dev/null &&
        ok "含 $want_dom" || no "缺 $want_dom"
done

# 视频流必须**不**在（台湾家宽扛不住）
for ban in youtube.com googlevideo.com ytimg.com; do
    jassert "$tmp/out.json" "'$ban' not in d['route']['rules'][0]['domain_suffix']" 2>/dev/null &&
        ok "不含 ${ban}（有意排除）" || no "不该含 $ban"
done

# googleapis.com 全量通配是**有意的**：需求就是「Google 系全走台湾」。
# 实测台湾带宽 7.1MB/s（香港直连 18.7MB/s），够用。
# 这里只断言它确实存在，防止将来有人误删导致 Google API 又回香港。
jassert "$tmp/out.json" '"googleapis.com" in d["route"]["rules"][0]["domain_suffix"]' 2>/dev/null &&
    ok "含 googleapis.com 全量通配（有意）" || no "缺 googleapis.com"

echo
echo "异常输入"

# 缺参数文件
if sh "$dir/gen-config.sh" "$tmp/nonexistent" >/dev/null 2>&1; then
    no "缺参数文件应当报错"
else
    ok "缺参数文件会报错"
fi

# 缺必填键
printf 'TW_SERVER=x\nTW_PORT=1\n' >"$tmp/bad.env"
if sh "$dir/gen-config.sh" "$tmp/bad.env" >/dev/null 2>&1; then
    no "缺 TW_METHOD/TW_PASSWORD 应当报错"
else
    ok "缺必填键会报错"
fi

# 密码含特殊字符（JSON 转义）
# 注意：期望值用 argv 传给 python，不走 jassert 的表达式字符串，
# 否则 " 和 \ 要经过 shell + heredoc 两层转义，极易写错。
cat >"$tmp/esc.env" <<'EOF'
TW_SERVER=tw.example.com
TW_PORT=50360
TW_METHOD=2022-blake3-aes-128-gcm
TW_PASSWORD=a"b\c:d
EOF
if sh "$dir/gen-config.sh" "$tmp/esc.env" >"$tmp/esc.json" 2>/dev/null &&
    python3 - "$tmp/esc.json" 'a"b\c:d' <<'PY'
import json, sys
got = json.load(open(sys.argv[1]))["outbounds"][0]["password"]
sys.exit(0 if got == sys.argv[2] else 1)
PY
then
    ok "密码含引号/反斜杠能正确转义"
else
    no "特殊字符转义"
fi

echo
printf '通过 %d，失败 %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
