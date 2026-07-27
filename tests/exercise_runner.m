// tests/exercise_runner.m - IOSDecryptHub hook 验证工具
//
// 这个程序把所有我们 hook 的 API 都调一遍, 然后停着等浏览器看.
// 用法 (macOS):
//   make test-mac
//   ./tests/exercise_runner --list-scenarios
//   ./tests/exercise_runner --scenario baseline.crypto.digest --timeout 30
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

#if defined(HAVE_OPENSSL) && HAVE_OPENSSL
#include <openssl/evp.h>
#endif

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <mach-o/dyld.h>
extern int ptrace(int, pid_t, caddr_t, int);
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

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

#if defined(HAVE_OPENSSL) && HAVE_OPENSSL
static void test_evp_aes(void) {
    printf("\n=== OpenSSL EVP AES-256-CBC ===\n");
    const char *pt = "openssl evp cipher test plaintext";
    unsigned char key[32], iv[16], ct[128];
    memset(key, 0x42, sizeof(key));
    memset(iv,  0x24, sizeof(iv));
    int outl = 0, finl = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { printf("  EVP_CIPHER_CTX_new failed\n"); return; }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        printf("  EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    if (EVP_EncryptUpdate(ctx, ct, &outl, (const unsigned char *)pt, (int)strlen(pt)) != 1) {
        printf("  EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    int total = outl;
    if (EVP_EncryptFinal_ex(ctx, ct + outl, &finl) != 1) {
        printf("  EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    total += finl;
    print_hex("evp-ct", ct, (size_t)total);
    EVP_CIPHER_CTX_free(ctx);
}
#endif

// Keychain: 增 → 查(dump data)→ 改 → 删 一条 generic password.
// 期望日志: SecItemAdd / SecItemCopyMatching(dump) / SecItemUpdate / SecItemDelete.
// 注: macOS 上 SecItem 走 login keychain, 可能因权限/无钥匙串失败, 失败也应有日志(status=...)。
static void test_keychain(void) {
    printf("\n=== Keychain SecItem ===\n");
    NSString *svc = @"com.dh.probe.service";
    NSString *acct = @"probe-account";
    NSData *secret = [@"kc-secret-token-9f8e7d" dataUsingEncoding:NSUTF8StringEncoding];

    NSDictionary *base = @{ (id)kSecClass: (id)kSecClassGenericPassword,
                            (id)kSecAttrService: svc,
                            (id)kSecAttrAccount: acct };
    // 先清一遍避免 duplicate
    SecItemDelete((__bridge CFDictionaryRef)base);

    NSMutableDictionary *add = [base mutableCopy];
    add[(id)kSecValueData] = secret;
    OSStatus a = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    printf("  SecItemAdd: %d\n", (int)a);

    NSMutableDictionary *q = [base mutableCopy];
    q[(id)kSecReturnData] = @YES;
    q[(id)kSecMatchLimit] = (id)kSecMatchLimitOne;
    CFTypeRef out = NULL;
    OSStatus c = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    printf("  SecItemCopyMatching: %d (len=%ld)\n", (int)c,
           out ? CFDataGetLength((CFDataRef)out) : -1L);
    if (out) CFRelease(out);

    NSDictionary *upd = @{ (id)kSecValueData: [@"kc-secret-ROTATED" dataUsingEncoding:NSUTF8StringEncoding] };
    OSStatus u = SecItemUpdate((__bridge CFDictionaryRef)base, (__bridge CFDictionaryRef)upd);
    printf("  SecItemUpdate: %d\n", (int)u);

    OSStatus d = SecItemDelete((__bridge CFDictionaryRef)base);
    printf("  SecItemDelete: %d\n", (int)d);
}

static volatile int gKeepRunning = 1;
static void on_sigint(int sig) { (void)sig; gKeepRunning = 0; }

// 环境探测 / 越狱绕过 / 反调试。jb 默认开 → /bin/bash(mac 真实存在, 在默认越狱清单)应被隐藏。
static void test_env(void) {
    printf("\n=== Env / jailbreak-bypass / anti-debug ===\n");
    errno = 0;
    int a = access("/bin/bash", F_OK);
    printf("  access(/bin/bash): ret=%d errno=%d (期望 -1/ENOENT=已隐藏)\n", a, errno);

    struct stat st;
    int s = stat("/bin/bash", &st);
    printf("  stat(/bin/bash): ret=%d (期望 -1)\n", s);

    int o = open("/bin/bash", O_RDONLY);
    printf("  open(/bin/bash): ret=%d (期望 -1)\n", o);
    if (o >= 0) close(o);

    int p = ptrace(31 /*PT_DENY_ATTACH*/, 0, 0, 0);
    printf("  ptrace(PT_DENY_ATTACH): ret=%d (期望 0=空转)\n", p);

    char machine[64] = {0}; size_t ml = sizeof(machine);
    sysctlbyname("hw.machine", machine, &ml, NULL, 0);
    printf("  sysctlbyname(hw.machine) = %s (device 开→期望伪造值)\n", machine);

    char model[64] = {0}; size_t modl = sizeof(model);
    sysctlbyname("hw.model", model, &modl, NULL, 0);
    printf("  sysctlbyname(hw.model) = %s (device 开→期望伪造值)\n", model);

    NSOperatingSystemVersion ov = [[NSProcessInfo processInfo] operatingSystemVersion];
    printf("  NSProcessInfo os = %ld.%ld.%ld (device 开→期望伪造值)\n",
           (long)ov.majorVersion, (long)ov.minorVersion, (long)ov.patchVersion);

    // csops: 反调试清 CS_DEBUGGED 验证。先探当前 flags, 观测/清位逻辑在 hook 内。
    uint32_t csflags = 0;
    int cr = csops(getpid(), 0 /*CS_OPS_STATUS*/, &csflags, sizeof(csflags));
    printf("  csops(CS_OPS_STATUS): ret=%d flags=0x%x (CS_DEBUGGED=0x10000000 应被清)\n", cr, csflags);
}

// 文件层: 写一个 /tmp 文件 (dh_is_app_file 认 "/tmp/"), 再 read 回来 + mmap 一次.
// 期望日志: open(写) / write / open(读) / read(dump 内容) / mmap.
static void test_file(void) {
    printf("\n=== File open/write/read/mmap ===\n");
    const char *path = "/tmp/dh_file_probe.bin";
    const char *payload = "sekret-token=abc123; device_id=DEADBEEF; probe file content";
    size_t plen = strlen(payload);

    int wfd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (wfd < 0) { printf("  open(write) failed\n"); return; }
    write(wfd, payload, plen);
    close(wfd);

    int rfd = open(path, O_RDONLY);
    if (rfd < 0) { printf("  open(read) failed\n"); return; }
    char buf[256] = {0};
    ssize_t rn = read(rfd, buf, sizeof(buf));
    printf("  read %zd bytes: %.*s\n", rn, (int)rn, buf);

    void *m = mmap(NULL, plen, PROT_READ, MAP_PRIVATE, rfd, 0);
    if (m != MAP_FAILED) { printf("  mmap ok @ %p\n", m); munmap(m, plen); }
    close(rfd);
}

// 注入痕迹隐藏: 遍历已加载 image, 自身 dylib 名应被改名隐藏(jb 默认开)。
static void test_inject(void) {
    printf("\n=== 注入痕迹隐藏 ===\n");
    uint32_t cnt = _dyld_image_count();
    int visible = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        const char *n = _dyld_get_image_name(i);
        if (n && strstr(n, "decrypt_helper")) { visible++; printf("  仍可见: %s\n", n); }
    }
    printf("  image 总数=%u, 含 decrypt_helper 的可见项=%d (期望 0=已隐藏)\n", cnt, visible);
}

// 网络 + X-Validator 场景: SHA256(body) -> base64 设为请求头, 供 correlate_request 反查命中。
// 打本机 8088(HTML 外壳免鉴权、瞬时响应), 让配对 net 事件快速落库。
static void test_network(void) {
    const char *bodyC = "{\"probe\":\"test\",\"secret\":\"s3cr3t\"}";
    NSData *body = [NSData dataWithBytes:bodyC length:strlen(bodyC)];
    unsigned char dg[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(body.bytes, (CC_LONG)body.length, dg);
    NSString *validator = [[NSData dataWithBytes:dg length:sizeof(dg)] base64EncodedStringWithOptions:0];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"http://127.0.0.1:8088/"]];
    req.HTTPMethod = @"POST";
    [req setValue:validator forHTTPHeaderField:@"X-Validator"];
    req.HTTPBody = body;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSessionDataTask *t = [[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) { dispatch_semaphore_signal(sem); }];
    [t resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)));
    printf("[exercise] network: X-Validator = base64(SHA256(body)) 已发\n");
}

// ============================================================
// 确定性场景注册表
// ============================================================

typedef void (*DHScenarioFn)(void);

typedef struct {
    const char *scenarioId;
    DHScenarioFn run;
} DHScenario;

static void scenario_rsa(void) { @autoreleasepool { test_rsa(); } }
static void scenario_keychain(void) { @autoreleasepool { test_keychain(); } }
static void scenario_network(void) { @autoreleasepool { test_network(); } }

static const DHScenario kScenarios[] = {
    { "baseline.crypto.digest",       test_digests },
    { "baseline.crypto.hmac",         test_hmac },
    { "baseline.crypto.aes-roundtrip", test_aes },
    { "baseline.crypto.rsa",          scenario_rsa },
    { "baseline.file.lifecycle",      test_file },
    { "baseline.keychain.lifecycle",  scenario_keychain },
    { "baseline.environment.probes",  test_env },
    { "baseline.injection.visibility",test_inject },
    { "baseline.network.request",     scenario_network },
};

static const size_t kScenarioCount = sizeof(kScenarios) / sizeof(kScenarios[0]);

static void print_scenarios(void) {
    for (size_t i = 0; i < kScenarioCount; i++) printf("%s\n", kScenarios[i].scenarioId);
}

static int run_scenario(const char *scenarioId) {
    for (size_t i = 0; i < kScenarioCount; i++) {
        if (strcmp(kScenarios[i].scenarioId, scenarioId) != 0) continue;
        printf("[scenario] START %s\n", scenarioId);
        kScenarios[i].run();
        printf("[scenario] DONE %s\n", scenarioId);
        return 1;
    }
    fprintf(stderr, "[scenario] UNKNOWN %s\n", scenarioId ?: "(null)");
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *selectedScenario = NULL;
    int holdSeconds = 600;
    int listOnly = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--list-scenarios") == 0) {
            listOnly = 1;
        } else if (strcmp(argv[i], "--scenario") == 0 && i + 1 < argc) {
            selectedScenario = argv[++i];
            holdSeconds = 30;
        } else if (strcmp(argv[i], "--all") == 0) {
            selectedScenario = NULL;
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            holdSeconds = atoi(argv[++i]);
            if (holdSeconds < 0 || holdSeconds > 3600) {
                fprintf(stderr, "--timeout 必须在 0..3600 秒之间\n");
                return 2;
            }
        } else {
            fprintf(stderr, "未知参数: %s\n", argv[i]);
            fprintf(stderr, "用法: %s [--list-scenarios] [--scenario ID|--all] [--timeout SEC]\n", argv[0]);
            return 2;
        }
    }

    if (listOnly) {
        print_scenarios();
        return 0;
    }

    printf("[exercise] PID %d — IOSDecryptHub hook 验证\n", getpid());
    printf("[exercise] 等 dylib 起 HTTP 服务 (1.5s)...\n");
    usleep(1500 * 1000);

    if (selectedScenario) {
        if (!run_scenario(selectedScenario)) return 2;
    } else {
        // 保留 main -> test_* 的直接调用，作为静态调用图/Xref 的确定性 fixture。
        printf("[scenario] START baseline.crypto.digest\n"); test_digests();
        printf("[scenario] DONE baseline.crypto.digest\n");
        printf("[scenario] START baseline.crypto.hmac\n"); test_hmac();
        printf("[scenario] DONE baseline.crypto.hmac\n");
        printf("[scenario] START baseline.crypto.aes-roundtrip\n"); test_aes();
        printf("[scenario] DONE baseline.crypto.aes-roundtrip\n");
#if defined(HAVE_OPENSSL) && HAVE_OPENSSL
        printf("[scenario] START baseline.crypto.evp\n"); test_evp_aes();
        printf("[scenario] DONE baseline.crypto.evp\n");
#endif
        printf("[scenario] START baseline.crypto.rsa\n"); @autoreleasepool { test_rsa(); }
        printf("[scenario] DONE baseline.crypto.rsa\n");
        printf("[scenario] START baseline.file.lifecycle\n"); test_file();
        printf("[scenario] DONE baseline.file.lifecycle\n");
        printf("[scenario] START baseline.keychain.lifecycle\n"); @autoreleasepool { test_keychain(); }
        printf("[scenario] DONE baseline.keychain.lifecycle\n");
        printf("[scenario] START baseline.environment.probes\n"); test_env();
        printf("[scenario] DONE baseline.environment.probes\n");
        printf("[scenario] START baseline.injection.visibility\n"); test_inject();
        printf("[scenario] DONE baseline.injection.visibility\n");
        printf("[scenario] START baseline.network.request\n"); @autoreleasepool { test_network(); }
        printf("[scenario] DONE baseline.network.request\n");
    }

    printf("\n[exercise] SCENARIOS_COMPLETE\n");
    printf("[exercise] 用浏览器打开 http://127.0.0.1:8088\n");
    printf("[exercise] 应该能看到 MD5 / SHA1 / SHA256 / SHA512 (4 摘要) +\n");
    printf("           SHA256-streaming + HMAC-SHA256/SHA1 + HMAC-streaming +\n");
    printf("           AES-128-CBC encrypt + AES-128-CBC decrypt (streaming) +\n");
#if defined(HAVE_OPENSSL) && HAVE_OPENSSL
    printf("           OpenSSL EVP AES-256-CBC +\n");
#endif
    printf("           RSA SIGN/VERIFY/ENC/DEC, 一共 ~12 条日志.\n");
    printf("[exercise] 另有 1 条 MGCopyAnswer 噪点 → 应出现在「噪点」tab, 不在加解密 tab.\n");
    printf("[exercise] Ctrl-C 退出. (%ds 后自动退)\n", holdSeconds);

    signal(SIGINT, on_sigint);
    for (int i = 0; i < holdSeconds && gKeepRunning; i++) sleep(1);
    return 0;
}
