# 解密助手 (Decrypt Helper) — iOS dylib
#
# 提供两条编译路径:
#   1) macOS xcrun (默认): 在 GitHub Actions / macOS 本机用
#       make                       -> decrypt_helper.dylib
#   2) Linux 交叉编译 (WSL): 需要环境变量 IOS_SDK 指向 iPhoneOS SDK 路径,
#       并且 CROSS_CC 指向支持 Apple target 的 clang.
#       export IOS_SDK=/path/to/iPhoneOS17.x.sdk
#       export CROSS_CC=/path/to/theos/toolchain/linux/iphone/bin/clang
#       make linux                 -> decrypt_helper.dylib

VERSION := 1.2.0
TARGET  := decrypt_helper.dylib
SRC     := src/fishhook.c \
           src/dh_health.c \
           src/log_store.m \
           src/hook_digest.m \
           src/hook_hmac.m \
           src/hook_symmetric.m \
           src/hook_asymmetric.m \
           src/hook_kdf.m \
           src/http_server.m \
           src/ui_float.m \
           src/ui_logview.m \
           src/main.m

FRAMEWORKS := -framework Foundation -framework UIKit -framework CoreGraphics -framework Security
ARCH       := arm64
MIN_IOS    := 14.0

# ---------- 1) macOS xcrun ----------
SDK     ?= $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
CC      ?= $(shell xcrun --find clang 2>/dev/null)

CFLAGS  := -arch $(ARCH) \
           -isysroot $(SDK) \
           -miphoneos-version-min=$(MIN_IOS) \
           -dynamiclib \
           -install_name @executable_path/$(TARGET) \
           -Xlinker -current_version -Xlinker $(VERSION) \
           -Xlinker -compatibility_version -Xlinker 1.0.0 \
           -ObjC -fobjc-arc \
           -Wall -Wno-deprecated-declarations -Wno-nullability-completeness \
           -Os \
           $(FRAMEWORKS)

all: $(TARGET)

$(TARGET): $(SRC) $(wildcard src/*.h)
	@echo "[*] 使用 $(CC) 编译..."
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)
	@echo "✅ 编译完成: $(TARGET)"

# ---------- 2) Linux 交叉编译 (WSL) ----------
linux:
	@if [ -z "$$IOS_SDK" ]; then echo "❌ 请先 export IOS_SDK=/path/to/iPhoneOS17.x.sdk"; exit 1; fi
	@if [ -z "$$CROSS_CC" ]; then echo "❌ 请先 export CROSS_CC=/path/to/clang (支持 apple target)"; exit 1; fi
	$$CROSS_CC \
	    -target arm64-apple-ios$(MIN_IOS) \
	    -isysroot $$IOS_SDK \
	    -dynamiclib \
	    -install_name @executable_path/$(TARGET) \
	    -Xlinker -current_version -Xlinker $(VERSION) \
	    -Xlinker -compatibility_version -Xlinker 1.0.0 \
	    -ObjC -fobjc-arc \
	    -Wall -Wno-deprecated-declarations -Wno-nullability-completeness \
	    -Os \
	    $(FRAMEWORKS) \
	    $(SRC) -o $(TARGET)
	@command -v ldid >/dev/null 2>&1 && ldid -S $(TARGET) && echo "✅ 已用 ldid 自签" || echo "⚠️ 未找到 ldid, 请手动签名"
	@echo "✅ 交叉编译完成: $(TARGET)"

# ---------- 3) macOS native (用于 Mac 上灰度测试) ----------
# 不带 UIKit (UI 代码自己用 __has_include 隔离了, 没 UIKit 就只编 stub),
# 只保留 hook + HTTP 服务. 浏览器开 http://127.0.0.1:8088 看效果.
MAC_TARGET := decrypt_helper.mac.dylib
MAC_SDK    := $(shell xcrun --sdk macosx --show-sdk-path 2>/dev/null)
MAC_ARCH   := $(shell uname -m)
MAC_MIN    := 11.0
MAC_FRAMEWORKS := -framework Foundation -framework CoreFoundation -framework Security
MAC_CFLAGS := -arch $(MAC_ARCH) \
              -isysroot $(MAC_SDK) \
              -mmacosx-version-min=$(MAC_MIN) \
              -dynamiclib \
              -install_name @rpath/$(MAC_TARGET) \
              -Xlinker -current_version -Xlinker $(VERSION) \
              -ObjC -fobjc-arc \
              -Wall -Wno-deprecated-declarations -Wno-nullability-completeness \
              -O0 -g \
              $(MAC_FRAMEWORKS)

mac: $(MAC_TARGET)

$(MAC_TARGET): $(SRC)
	@if [ -z "$(MAC_SDK)" ]; then echo "❌ 没找到 macOS SDK, 请先装 Xcode 或 CommandLineTools"; exit 1; fi
	@echo "[*] macOS 原生编译 (arch=$(MAC_ARCH), min=$(MAC_MIN))..."
	$(CC) $(MAC_CFLAGS) $(SRC) -o $(MAC_TARGET)
	@echo "✅ macOS dylib: $(MAC_TARGET)"

# ---------- 4) Mac 灰度测试 ----------
# 编 dylib + 编 exercise_runner + DYLD_INSERT_LIBRARIES 跑.
# 跑完浏览器开 http://127.0.0.1:8088 应该能看到 ~12 条日志.
TEST_BIN := tests/exercise_runner

test-mac: $(MAC_TARGET) $(TEST_BIN)
	@echo "[*] 启动测试: DYLD_INSERT_LIBRARIES=$(MAC_TARGET) $(TEST_BIN)"
	@echo "[*] 一秒后请打开 http://127.0.0.1:8088"
	DYLD_INSERT_LIBRARIES=./$(MAC_TARGET) ./$(TEST_BIN)

$(TEST_BIN): tests/exercise_runner.m
	@if [ -z "$(MAC_SDK)" ]; then echo "❌ 没找到 macOS SDK"; exit 1; fi
	@echo "[*] 编 exercise_runner ..."
	$(CC) -arch $(MAC_ARCH) -isysroot $(MAC_SDK) -mmacosx-version-min=$(MAC_MIN) \
	      -ObjC -fobjc-arc -Wall -Wno-deprecated-declarations -O0 -g \
	      -framework Foundation -framework CoreFoundation -framework Security \
	      tests/exercise_runner.m -o $(TEST_BIN)
	@echo "✅ test runner: $(TEST_BIN)"

clean:
	rm -f $(TARGET) $(MAC_TARGET) $(TEST_BIN)

.PHONY: all linux mac test-mac clean
