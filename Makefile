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

VERSION := 1.21.0
TARGET  := decrypt_helper.dylib

# Capstone 反汇编库源文件（仅 ARM/ARM64 架构）
CAPSTONE_SRC := src/core/capstone/cs.c \
                src/core/capstone/utils.c \
                src/core/capstone/SStream.c \
                src/core/capstone/MCInst.c \
                src/core/capstone/MCInstrDesc.c \
                src/core/capstone/MCRegisterInfo.c \
                src/core/capstone/Mapping.c \
                src/core/capstone/arch/ARM/ARMDisassembler.c \
                src/core/capstone/arch/ARM/ARMInstPrinter.c \
                src/core/capstone/arch/ARM/ARMMapping.c \
                src/core/capstone/arch/ARM/ARMModule.c \
                src/core/capstone/arch/AArch64/AArch64BaseInfo.c \
                src/core/capstone/arch/AArch64/AArch64Disassembler.c \
                src/core/capstone/arch/AArch64/AArch64InstPrinter.c \
                src/core/capstone/arch/AArch64/AArch64Mapping.c \
                src/core/capstone/arch/AArch64/AArch64Module.c

SRC     := src/core/fishhook.c \
           src/core/dh_health.c \
           src/core/dh_capture.c \
           src/core/dh_noise.m \
           src/core/dh_spoof.m \
           src/core/dh_symtab.c \
           src/core/dh_dlsym_redirect.c \
           src/core/log_store.m \
           src/core/zip_writer.c \
           src/core/macho_dump.m \
           src/core/dump_manager.m \
           src/core/dh_files.m \
           src/core/analysis.m \
           src/hooks/crypto/hook_digest.m \
           src/hooks/crypto/hook_hmac.m \
           src/hooks/crypto/hook_symmetric.m \
           src/hooks/crypto/hook_asymmetric.m \
           src/hooks/crypto/hook_kdf.m \
           src/hooks/crypto/hook_evp.m \
           src/hooks/behavior/hook_file.m \
           src/hooks/behavior/hook_system.m \
           src/hooks/behavior/hook_keychain.m \
           src/hooks/behavior/hook_env.m \
           src/hooks/behavior/hook_spoof_objc.m \
           src/hooks/behavior/hook_dyld.m \
           src/hooks/behavior/hook_network.m \
           src/server/http_server.m \
           src/server/mcp_server.m \
           src/server/dh_log_json.m \
           src/ui/ui_float.m \
           src/ui/ui_logview.m \
           src/core/main.m \
           $(CAPSTONE_SRC)

FRAMEWORKS := -framework Foundation -framework UIKit -framework CoreGraphics -framework Security

# Capstone 编译宏 (缺一不可, 否则运行时失败):
#   CAPSTONE_USE_SYS_DYN_MEM — 用系统 malloc/free, 否则 cs_open 返回 CS_ERR_MEMSETUP
#   CAPSTONE_HAS_ARM / _ARM64 — 注册 ARM/AArch64 架构, 否则 cs_open 返回 CS_ERR_ARCH
CAPSTONE_DEF := -DCAPSTONE_USE_SYS_DYN_MEM -DCAPSTONE_HAS_ARM -DCAPSTONE_HAS_ARM64

# 挂到共享的 INCLUDES 上, 让 4 个编译目标 (iOS/mac/sim/linux) 都带上。
# 版本号单一真相源 = 上面的 VERSION; 经 -D 注入, http_server/mcp_server 不再各自硬编码。
INCLUDES   := -Isrc/core -Isrc/core/capstone/include -Isrc/server -Isrc/ui $(CAPSTONE_DEF) -DDH_VERSION_STR='"$(VERSION)"'
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
           $(INCLUDES) \
           $(FRAMEWORKS)

all: $(TARGET)

# 前端: 改 web/index.html 后自动重生成内嵌头(字节数组), 不再手刮 C 字符串。
WEB_HEADER := src/server/web_index_html.h
$(WEB_HEADER): web/index.html tools/gen_web.py
	@echo "[*] 生成前端内嵌头 $(WEB_HEADER) ..."
	python3 tools/gen_web.py web/index.html $(WEB_HEADER)

$(TARGET): $(WEB_HEADER) $(SRC) $(wildcard src/*/*.h)
	@echo "[*] 使用 $(CC) 编译..."
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)
	@echo "✅ 编译完成: $(TARGET)"

# ---------- 2) Linux 交叉编译 (WSL) ----------
.PHONY: linux
linux: $(WEB_HEADER)
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
	    $(INCLUDES) \
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
              $(INCLUDES) \
              $(MAC_FRAMEWORKS)

mac: $(WEB_HEADER) $(MAC_TARGET)

$(MAC_TARGET): $(WEB_HEADER) $(SRC)
	@if [ -z "$(MAC_SDK)" ]; then echo "❌ 没找到 macOS SDK, 请先装 Xcode 或 CommandLineTools"; exit 1; fi
	@echo "[*] macOS 原生编译 (arch=$(MAC_ARCH), min=$(MAC_MIN))..."
	$(CC) $(MAC_CFLAGS) $(SRC) -o $(MAC_TARGET)
	@echo "✅ macOS dylib: $(MAC_TARGET)"

# ---------- 3b) iOS Simulator (真 UIKit / file / dlopen 环境, 注入模拟器 App 测试) ----------
SIM_TARGET := decrypt_helper.sim.dylib
SIM_SDK    := $(shell xcrun --sdk iphonesimulator --show-sdk-path 2>/dev/null)
SIM_ARCH   := $(shell uname -m)
SIM_MIN    := 14.0
SIM_CFLAGS := -target $(SIM_ARCH)-apple-ios$(SIM_MIN)-simulator \
              -isysroot $(SIM_SDK) \
              -dynamiclib \
              -install_name @executable_path/$(SIM_TARGET) \
              -ObjC -fobjc-arc \
              -Wall -Wno-deprecated-declarations -Wno-nullability-completeness \
              -O0 -g \
              $(INCLUDES) \
              $(FRAMEWORKS)

sim: $(WEB_HEADER) $(SIM_TARGET)

$(SIM_TARGET): $(WEB_HEADER) $(SRC)
	@if [ -z "$(SIM_SDK)" ]; then echo "❌ 没找到 iPhoneSimulator SDK"; exit 1; fi
	@echo "[*] iOS Simulator 编译 (arch=$(SIM_ARCH), min=$(SIM_MIN))..."
	$(CC) $(SIM_CFLAGS) $(SRC) -o $(SIM_TARGET)
	codesign -s - -f $(SIM_TARGET) 2>/dev/null || true
	@echo "✅ simulator dylib: $(SIM_TARGET)"

# ---------- 4) Mac 灰度测试 ----------
# 编 dylib + 编 exercise_runner + DYLD_INSERT_LIBRARIES 跑.
# 跑完浏览器开 http://127.0.0.1:8088 应该能看到 ~12 条日志.
TEST_BIN := tests/exercise_runner
OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null)
TEST_OPENSSL_CFLAGS :=
TEST_OPENSSL_LIBS :=
ifneq ($(OPENSSL_PREFIX),)
ifneq ($(wildcard $(OPENSSL_PREFIX)/include/openssl/evp.h),)
TEST_OPENSSL_CFLAGS := -I$(OPENSSL_PREFIX)/include -DHAVE_OPENSSL=1
TEST_OPENSSL_LIBS := -L$(OPENSSL_PREFIX)/lib -lcrypto
endif
endif

test-mac: $(MAC_TARGET) $(TEST_BIN)
	@echo "[*] 启动测试: DYLD_INSERT_LIBRARIES=$(MAC_TARGET) $(TEST_BIN)"
	@echo "[*] 一秒后请打开 http://127.0.0.1:8088"
	DYLD_INSERT_LIBRARIES=./$(MAC_TARGET) ./$(TEST_BIN)

# 自动化集成测试: 注入 dylib 到 runner, 驱动真实 MCP/HTTP 端点断言 (认证/工具/查询/关联/诊断)。
.PHONY: test-mcp
test-mcp:
	@chmod +x tests/mcp_test.sh
	./tests/mcp_test.sh

$(TEST_BIN): tests/exercise_runner.m
	@if [ -z "$(MAC_SDK)" ]; then echo "❌ 没找到 macOS SDK"; exit 1; fi
	@echo "[*] 编 exercise_runner ..."
	$(CC) -arch $(MAC_ARCH) -isysroot $(MAC_SDK) -mmacosx-version-min=$(MAC_MIN) \
	      -ObjC -fobjc-arc -Wall -Wno-deprecated-declarations -O0 -g \
	      $(TEST_OPENSSL_CFLAGS) \
	      -framework Foundation -framework CoreFoundation -framework Security \
	      tests/exercise_runner.m -o $(TEST_BIN) $(TEST_OPENSSL_LIBS)
	@echo "✅ test runner: $(TEST_BIN)"

# ---------- 5) 发布产物: 带版本号的 dylib ----------
# release 资产用带版本号的文件名, 方便区分不同版本的下载。
# 文件名与 install_name(LC_ID) 都带版本; inject.sh 从文件名推导 LC_LOAD_DYLIB, 故注入仍自洽。
# 主构建产物保持 decrypt_helper.dylib 不变(测试 IPA / inject 默认名不受影响)。
DIST_DYLIB := decrypt_helper-$(VERSION).dylib
dist: $(TARGET)
	cp $(TARGET) $(DIST_DYLIB)
	install_name_tool -id @executable_path/$(DIST_DYLIB) $(DIST_DYLIB)
	@echo "✅ 发布产物: $(DIST_DYLIB)"

# ---------- 6) 模拟器一键部署 (sim_uitest + 注入 sim dylib) ----------
sim-install:
	@chmod +x scripts/sim_install.sh
	./scripts/sim_install.sh

clean:
	rm -f $(TARGET) $(MAC_TARGET) $(SIM_TARGET) $(TEST_BIN) decrypt_helper-*.dylib
	rm -rf build/sim

.PHONY: all linux mac sim test-mac sim-install dist clean
