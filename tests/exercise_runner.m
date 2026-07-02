// tests/exercise_runner.m - IOSDecryptHub hook 验证工具
//
// 这个程序把所有我们 hook 的 API 都调一遍, 然后停着等浏览器看.
// 用法 (macOS):
//   make test-mac
// 它会:
//   1. 用 macOS target 编译 decrypt_helper.mac.dylib (不带 UI, 只有 hook + HTTP)
//   2. 编出 exercise_runner
//   3. DYLD_INSERT_LIBRARIES=decrypt_helper.mac.dylib ./exercise_runner
//   4. 程序里逐个调用 CC_MD5 / SHA256 / HMAC-SHA256 / AES-128-CBC / RSA 签名
//   5. sleep 5 分钟, 你打开 http://127.0.0.1:8088 看, 应能看到 ~10 条日志
//   6. 没看到 = hook 失效, 看到 = 完全 OK

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

static void print_hex(const char *label, const unsigned char *b, size_t n) {
    printf("  %s (%zu): ", label, n);
    for (size_t i = 0; i < n && i < 32; i++) printf("%02x", b[i]);
    if (n > 32) printf("...");
    printf("\n");
}

static void test_digests(void) {
    const char *msg = "the quick brown fox jumps over the lazy dog";
    size_t len = strlen(msg);

    printf("\n=== Digest ===\n");

    // 一次性
    unsigned char md5[CC_MD5_DIGEST_LENGTH];
    CC_MD5(msg, (CC_LONG)len, md5);
    print_hex("MD5      ", md5, CC_MD5_DIGEST_LENGTH);

    // 噪点分流演示: 模拟 iOS MobileGestalt 内部缓存键 (业务无关噪点)。默认特征串 "MGCopyAnswer"
    // 命中后, 这条不进主事件流(加解密 tab), 而被路由到独立的「噪点」tab, 便于回归验证噪点机制。
    const char *noise = "MGCopyAnswerapple-internal-install";
    unsigned char md5n[CC_MD5_DIGEST_LENGTH];
    CC_MD5(noise, (CC_LONG)strlen(noise), md5n);
    print_hex("MD5-noise", md5n, CC_MD5_DIGEST_LENGTH);

    unsigned char sha1[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(msg, (CC_LONG)len, sha1);
    print_hex("SHA1     ", sha1, CC_SHA1_DIGEST_LENGTH);

    unsigned char sha256[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(msg, (CC_LONG)len, sha256);
    print_hex("SHA256   ", sha256, CC_SHA256_DIGEST_LENGTH);

    unsigned char sha512[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(msg, (CC_LONG)len, sha512);
    print_hex("SHA512   ", sha512, CC_SHA512_DIGEST_LENGTH);

    // 流式 (切两半喂)
    unsigned char sha256s[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, msg, (CC_LONG)(len / 2));
    CC_SHA256_Update(&ctx, msg + len / 2, (CC_LONG)(len - len / 2));
    CC_SHA256_Final(sha256s, &ctx);
    print_hex("SHA256-S ", sha256s, CC_SHA256_DIGEST_LENGTH);
}

static void test_hmac(void) {
    const char *key = "shared-secret-key";
    const char *msg = "important transaction data";
    printf("\n=== HMAC ===\n");

    unsigned char m1[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key, strlen(key), msg, strlen(msg), m1);
    print_hex("HMAC-SHA256       ", m1, CC_SHA256_DIGEST_LENGTH);

    unsigned char m2[CC_SHA1_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA1, key, strlen(key), msg, strlen(msg), m2);
    print_hex("HMAC-SHA1         ", m2, CC_SHA1_DIGEST_LENGTH);

    // 流式
    CCHmacContext c;
    CCHmacInit(&c, kCCHmacAlgSHA256, key, strlen(key));
    CCHmacUpdate(&c, msg, strlen(msg) / 2);
    CCHmacUpdate(&c, msg + strlen(msg) / 2, strlen(msg) - strlen(msg) / 2);
    unsigned char m3[CC_SHA256_DIGEST_LENGTH];
    CCHmacFinal(&c, m3);
    print_hex("HMAC-SHA256-stream", m3, CC_SHA256_DIGEST_LENGTH);
}

static void test_aes(void) {
    printf("\n=== AES-128-CBC ===\n");
    unsigned char key[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                             0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    unsigned char iv[16]  = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                             0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    const char *pt = "the answer is 42; this is a longer plaintext for AES";
    unsigned char ct[128] = {0};
    size_t outLen = 0;
    CCCryptorStatus s = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                 key, sizeof(key), iv, pt, strlen(pt),
                                 ct, sizeof(ct), &outLen);
    if (s == kCCSuccess) print_hex("ciphertext", ct, outLen);
    else                 printf("  AES encrypt failed: %d\n", s);

    // 解密回明文 (测试 CCCryptor* 流式)
    CCCryptorRef cr = NULL;
    CCCryptorCreate(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                    key, sizeof(key), iv, &cr);
    unsigned char dec[128] = {0}; size_t off = 0, n = 0;
    CCCryptorUpdate(cr, ct, outLen, dec, sizeof(dec), &n);   off += n;
    CCCryptorFinal(cr, dec + off, sizeof(dec) - off, &n);    off += n;
    CCCryptorRelease(cr);
    printf("  plaintext (%zu): %.*s\n", off, (int)off, dec);
}

static void test_rsa(void) {
    printf("\n=== RSA-2048 sign + verify ===\n");
    // 临时生成一对 RSA 密钥
    NSDictionary *params = @{
        (id)kSecAttrKeyType:       (id)kSecAttrKeyTypeRSA,
        (id)kSecAttrKeySizeInBits: @2048,
    };
    CFErrorRef err = NULL;
    SecKeyRef priv = SecKeyCreateRandomKey((CFDictionaryRef)params, &err);
    if (!priv) {
        NSError *e = err ? (__bridge_transfer NSError *)err : nil;
        printf("  RSA keygen failed: %s\n", e.localizedDescription.UTF8String ?: "?");
        return;
    }
    SecKeyRef pub = SecKeyCopyPublicKey(priv);

    const char *msg = "transfer 100 to bob";
    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)msg, strlen(msg));

    CFDataRef sig = SecKeyCreateSignature(priv,
        kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
        data, &err);
    if (sig) {
        print_hex("signature ", CFDataGetBytePtr(sig), MIN((size_t)CFDataGetLength(sig), 32UL));
        Boolean ok = SecKeyVerifySignature(pub,
            kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
            data, sig, &err);
        printf("  verify   : %s\n", ok ? "ok" : "FAIL");
        CFRelease(sig);
    } else {
        printf("  sign failed\n");
    }

    // 加解密
    CFDataRef ct = SecKeyCreateEncryptedData(pub,
        kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
        data, &err);
    if (ct) {
        print_hex("rsa-ct    ", CFDataGetBytePtr(ct), MIN((size_t)CFDataGetLength(ct), 32UL));
        CFDataRef pt = SecKeyCreateDecryptedData(priv,
            kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
            ct, &err);
        if (pt) {
            printf("  rsa-pt    (%ld): %.*s\n",
                CFDataGetLength(pt), (int)CFDataGetLength(pt), CFDataGetBytePtr(pt));
            CFRelease(pt);
        }
        CFRelease(ct);
    }

    CFRelease(data); CFRelease(priv); if (pub) CFRelease(pub);
}

static volatile int gKeepRunning = 1;
static void on_sigint(int sig) { (void)sig; gKeepRunning = 0; }

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[exercise] PID %d — IOSDecryptHub hook 验证\n", getpid());
    printf("[exercise] 等 dylib 起 HTTP 服务 (1.5s)...\n");
    usleep(1500 * 1000);

    test_digests();
    test_hmac();
    test_aes();
    @autoreleasepool { test_rsa(); }

    printf("\n[exercise] 全部 hook 调用完毕.\n");
    printf("[exercise] 用浏览器打开 http://127.0.0.1:8088\n");
    printf("[exercise] 应该能看到 MD5 / SHA1 / SHA256 / SHA512 (4 摘要) +\n");
    printf("           SHA256-streaming + HMAC-SHA256/SHA1 + HMAC-streaming +\n");
    printf("           AES-128-CBC encrypt + AES-128-CBC decrypt (streaming) +\n");
    printf("           RSA SIGN/VERIFY/ENC/DEC, 一共 ~12 条日志.\n");
    printf("[exercise] 另有 1 条 MGCopyAnswer 噪点 → 应出现在「噪点」tab, 不在加解密 tab.\n");
    printf("[exercise] Ctrl-C 退出. (默认 600s 自动退)\n");

    signal(SIGINT, on_sigint);
    for (int i = 0; i < 600 && gKeepRunning; i++) sleep(1);
    return 0;
}
