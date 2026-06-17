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

VERSION := 1.0.0
TARGET  := decrypt_helper.dylib
SRC     := src/fishhook.c \
           src/log_store.m \
           src/hook_digest.m \
           src/hook_hmac.m \
           src/hook_symmetric.m \
           src/hook_asymmetric.m \
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

$(TARGET): $(SRC)
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

clean:
	rm -f $(TARGET)

.PHONY: all linux clean
