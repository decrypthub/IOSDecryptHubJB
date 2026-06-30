#!/usr/bin/env python3
# gen_web.py — 把 web/index.html 编成 C 字节数组头, 嵌入 dylib。
# 零运行时依赖、免转义: 前端正常写 web/index.html, make 时自动生成本头。
# 用法: python3 tools/gen_web.py web/index.html src/server/web_index_html.h
import sys

def main():
    if len(sys.argv) != 3:
        print("用法: gen_web.py <input.html> <output.h>", file=sys.stderr)
        sys.exit(2)
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, "rb").read()
    out = []
    out.append("// AUTO-GENERATED from web/index.html by tools/gen_web.py — 请勿手改, 改 web/index.html 后 make 自动重生成。")
    out.append("#ifndef DH_WEB_INDEX_HTML_H")
    out.append("#define DH_WEB_INDEX_HTML_H")
    out.append("static const unsigned char kDHIndexHTML[] = {")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        out.append("  " + "".join("0x%02x," % b for b in chunk))
    out.append("};")
    out.append("static const unsigned int kDHIndexHTML_len = %d;" % len(data))
    out.append("#endif // DH_WEB_INDEX_HTML_H")
    open(dst, "w").write("\n".join(out) + "\n")
    print("generated %s (%d bytes)" % (dst, len(data)))

if __name__ == "__main__":
    main()
