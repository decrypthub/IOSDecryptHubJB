// jb_runner.m — 越狱设备 arm64e 引擎验证宿主 (DYLD_INSERT_LIBRARIES 注入用)
//
// 目的: 在真 arm64e / PAC 环境下, 让注入的 decrypt_helper 挂上 import hook(CCCrypt/CC_SHA256),
// 验证 thunk-bank 的 br x16 尾调用在 PAC 下能正确转发不崩。进程常驻, dylib 的 8088 服务随之存活。
//
// 编译: xcrun -sdk iphoneos clang -arch arm64e -miphoneos-version-min=15.0 \
//         -ObjC -fobjc-arc tests/jb_runner.m -o jb_runner -framework Foundation
//        ldid -S jb_runner
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <unistd.h>
#import <stdio.h>

int main(void) {
    @autoreleasepool {
        fprintf(stderr, "[jb_runner] pid=%d 启动 (arm64e); 每 800ms 触发 CCCrypt+SHA256\n", getpid());
        fflush(stderr);
        unsigned char key[16] = {0}, iv[16] = {0}, in[32] = {1}, out[64];
        size_t moved = 0;
        unsigned long n = 0;
        while (1) {
            // 主二进制直接调 CommonCrypto → fishhook 可重绑其 import → hook_import 能抓到。
            CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                    key, 16, iv, in, sizeof(in), out, sizeof(out), &moved);
            unsigned char digest[CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(in, (CC_LONG)sizeof(in), digest);
            if (++n % 12 == 0) { fprintf(stderr, "[jb_runner] 存活, cycles=%lu\n", n); fflush(stderr); }
            usleep(800 * 1000);
        }
    }
    return 0;
}
