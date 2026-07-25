#!/bin/bash
# dh_listapps — 以 root 权限枚举已安装 App, 输出 JSON
# 使用 uicache -l 获取完整 App 列表
# 输出: /var/jb/var/mobile/Library/Preferences/com.dh.applist.json

OUT="/var/jb/tmp/com.dh.applist.json"
TMP="${OUT}.tmp"

uicache -l 2>/dev/null | awk '
BEGIN { printf "[\n" }
{
    bid = $1
    # 路径在 " : " 之后
    idx = index($0, " : ")
    if (idx == 0) next
    path = substr($0, idx + 3)

    # 从路径提取 app 名
    n = split(path, parts, "/")
    name = parts[n]
    sub(/\.app$/, "", name)

    # 判断系统 App
    is_sys = "false"
    if (path ~ /^\/Applications\//) is_sys = "true"
    if (bid ~ /^com\.apple\./) is_sys = "true"

    # 转义引号
    gsub(/"/, "\\\"", name)
    gsub(/"/, "\\\"", bid)

    if (NR > 1) printf ",\n"
    printf "{\"bundleId\":\"%s\",\"name\":\"%s\",\"isSystem\":%s}", bid, name, is_sys
}
END { printf "\n]\n" }
' > "$TMP"

mv "$TMP" "$OUT"
chmod 644 "$OUT"
