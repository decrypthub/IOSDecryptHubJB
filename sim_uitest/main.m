// sim_uitest/main.m — IOSDecryptHub 交互式测试台
// 顶部 segment 分 tab(加解密 / 系统), 每个 tab 的按钮触发对应一类系统调用,
// 便于在注入的 dylib 里逐个观察 hook 效果。不把所有按钮堆在一页。
//
// 自动化测试通道: 注册 URL scheme "dhtest", xcrun simctl openurl <dev> dhtest://md5
// 会通过 sendActionsForControlEvents: 模拟点击对应按钮(即使该 tab 当前隐藏)。

#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>
#import <dlfcn.h>
#import <unistd.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <mach-o/dyld.h>

extern int ptrace(int, pid_t, caddr_t, int);
#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

// 运行时从注入的 dylib 取真实服务地址(端口在 8088..8108 间自动顺延), 避免写死端口
static NSString *gUrlHint = @"";
static NSString *dh_real_url(void) {
    NSString *(*fn)(void) = (NSString *(*)(void))dlsym(RTLD_DEFAULT, "dh_http_url");
    if (!fn) return nil;
    NSString *u = fn();
    return (u && ![u hasPrefix:@"("]) ? u : nil;
}

@interface DHLogViewer : NSObject
+ (void)presentFromFloating;
@end

// ==================== 算法触发(加解密 tab) ====================
static const char *kMsg = "decrypt-helper interactive test sample";

static void do_digest(int which) {
    const char *m = kMsg; size_t n = strlen(m);
    if      (which == 0) { unsigned char d[CC_MD5_DIGEST_LENGTH];    CC_MD5(m, (CC_LONG)n, d); }
    else if (which == 1) { unsigned char d[CC_SHA1_DIGEST_LENGTH];   CC_SHA1(m, (CC_LONG)n, d); }
    else if (which == 2) { unsigned char d[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(m, (CC_LONG)n, d); }
    else                 { unsigned char d[CC_SHA512_DIGEST_LENGTH]; CC_SHA512(m, (CC_LONG)n, d); }
}
static void do_hmac(void) {
    const char *k = "secret-key", *m = kMsg;
    unsigned char o[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, k, strlen(k), m, strlen(m), o);
}
static void do_sym(CCAlgorithm alg, size_t keyLen, size_t blockLen) {
    unsigned char key[32] = {0}, iv[16] = {0};
    for (size_t i = 0; i < keyLen;   i++) key[i] = (unsigned char)i;
    for (size_t i = 0; i < blockLen; i++) iv[i]  = (unsigned char)(i + 0x10);
    const char *m = kMsg; unsigned char out[256]; size_t mv = 0;
    CCCrypt(kCCEncrypt, alg, kCCOptionPKCS7Padding, key, keyLen,
            blockLen ? iv : NULL, m, strlen(m), out, sizeof(out), &mv);
}
static void do_rc4(void) {
    unsigned char key[16]; for (int i = 0; i < 16; i++) key[i] = (unsigned char)i;
    const char *m = kMsg; unsigned char out[256]; size_t mv = 0;
    CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0, key, sizeof(key), NULL, m, strlen(m), out, sizeof(out), &mv);
}
static SecKeyRef gRSA = NULL;
static SecKeyRef rsa_key(void) {
    if (gRSA) return gRSA;
    NSDictionary *p = @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA, (id)kSecAttrKeySizeInBits: @2048 };
    gRSA = SecKeyCreateRandomKey((CFDictionaryRef)p, NULL);
    return gRSA;
}
static void do_rsa_sign(void) {
    SecKeyRef pk = rsa_key(); if (!pk) return;
    CFDataRef d = CFDataCreate(NULL, (const UInt8 *)kMsg, strlen(kMsg));
    CFDataRef s = SecKeyCreateSignature(pk, kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256, d, NULL);
    if (s) CFRelease(s);
    CFRelease(d);
}
static void do_rsa_enc(void) {
    SecKeyRef pk = rsa_key(); if (!pk) return;
    SecKeyRef pub = SecKeyCopyPublicKey(pk); if (!pub) return;
    CFDataRef d = CFDataCreate(NULL, (const UInt8 *)kMsg, strlen(kMsg));
    CFDataRef c = SecKeyCreateEncryptedData(pub, kSecKeyAlgorithmRSAEncryptionOAEPSHA256, d, NULL);
    if (c) CFRelease(c);
    CFRelease(d); CFRelease(pub);
}
static void do_pbkdf(void) {
    unsigned char dk[32];
    CCKeyDerivationPBKDF(kCCPBKDF2, "user-password", strlen("user-password"),
                         (const uint8_t *)"saltsalt", 8, kCCPRFHmacAlgSHA256, 10000, dk, sizeof(dk));
}
static void do_bigdata(void) {
    size_t n = 128 * 1024;
    unsigned char *b = malloc(n), *c = malloc(n + 16);
    if (b && c) {
        memset(b, 'A', n);
        unsigned char key[16] = {0}, iv[16] = {0}; size_t mv = 0;
        CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, key, 16, iv, b, n, c, n + 16, &mv);
    }
    free(b); free(c);
}

// ==================== 文件触发(文件 tab) ====================
static NSString *test_file_path(void) {
    NSArray *p = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    return [[p firstObject] stringByAppendingPathComponent:@"iosdh_test.txt"];
}
static void do_file_write(void) {
    NSString *p = test_file_path();
    int fd = open(p.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *data = "IOSDecryptHub file hook test - 文件操作测试数据\n";
        write(fd, data, strlen(data));
        close(fd);
    }
}
static void do_file_read(void) {
    NSString *p = test_file_path();
    int fd = open(p.UTF8String, O_RDONLY);
    if (fd >= 0) { char buf[256]; read(fd, buf, sizeof(buf)); close(fd); }
}
static void do_file_delete(void) {
    NSString *p = test_file_path();
    unlink(p.UTF8String);
}
static void do_file_rename(void) {
    NSString *from = test_file_path();
    NSString *to = [from stringByAppendingPathExtension:@"bak"];
    [@"rename test" writeToFile:from atomically:YES encoding:NSUTF8StringEncoding error:nil];
    rename(from.UTF8String, to.UTF8String);
}

// ==================== 系统触发(系统 tab) ====================
static void do_dlopen(void) {
    void *h1 = dlopen("/usr/lib/libsqlite3.dylib", RTLD_LAZY); if (h1) dlclose(h1);
    void *h2 = dlopen("/usr/lib/libz.dylib", RTLD_LAZY);       if (h2) dlclose(h2);
}
static void do_dlsym(void) {
    // 走 dlsym 路径调用 CC_MD5 / CCCrypt —— 验证 dlsym hook 重定向到 wrapper
    unsigned char *(*md5_fn)(const void *, CC_LONG, unsigned char *) =
        (unsigned char *(*)(const void *, CC_LONG, unsigned char *))dlsym(RTLD_DEFAULT, "CC_MD5");
    if (md5_fn) {
        unsigned char d[CC_MD5_DIGEST_LENGTH];
        md5_fn(kMsg, (CC_LONG)strlen(kMsg), d);
    }
    CCCryptorStatus (*crypt_fn)(CCOperation, CCAlgorithm, CCOptions,
                                const void *, size_t, const void *,
                                const void *, size_t, void *, size_t, size_t *) =
        (CCCryptorStatus (*)(CCOperation, CCAlgorithm, CCOptions,
                             const void *, size_t, const void *,
                             const void *, size_t, void *, size_t, size_t *))dlsym(RTLD_DEFAULT, "CCCrypt");
    if (crypt_fn) {
        unsigned char key[16] = {0}, iv[16] = {0}, out[256]; size_t mv = 0;
        crypt_fn(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, key, 16, iv,
                 kMsg, strlen(kMsg), out, sizeof(out), &mv);
    }
}
static void do_network(void) {
    // 发一个带 body 的 POST, 触发 -[NSURLSessionTask resume] swizzle (抓 URL/header/body)
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://httpbin.org/post"]];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"DecryptHubTest/1.0" forHTTPHeaderField:@"X-DH-Probe"];
    req.HTTPBody = [@"{\"probe\":\"network-capture\",\"secret\":\"s3cr3t\"}" dataUsingEncoding:NSUTF8StringEncoding];
    NSURLSessionDataTask *t = [[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) { /* 结果无所谓, 目的是触发 resume */ }];
    [t resume];
}

// ==================== 伪装/绕过自检(自检 tab) ====================
// 每项直接调用检测手法, 反推伪装是否生效, 返回可读结果。同时这些调用会被 dylib 观测并落日志。

static NSString *chk_jailbreak_files(void) {
    const char *paths[] = { "/Applications/Cydia.app", "/bin/bash", "/etc/apt", "/var/jb", "/usr/sbin/sshd" };
    NSMutableString *s = [NSMutableString stringWithString:@"[越狱文件探测]\n"];
    for (int i = 0; i < 5; i++) {
        struct stat st;
        BOOL visible = (access(paths[i], F_OK) == 0) || (stat(paths[i], &st) == 0);
        [s appendFormat:@"  %s → %@\n", paths[i], visible ? @"可见!(未隐藏)" : @"已隐藏"];
    }
    return s;
}

static NSString *chk_url_schemes(void) {
    NSArray<NSString *> *schemes = @[ @"cydia", @"sileo", @"filza", @"zbra" ];
    NSMutableString *s = [NSMutableString stringWithString:@"[URL Scheme 探测 canOpenURL]\n"];
    UIApplication *app = [UIApplication sharedApplication];
    for (NSString *sc in schemes) {
        NSURL *u = [NSURL URLWithString:[sc stringByAppendingString:@"://package"]];
        BOOL can = [app canOpenURL:u];
        [s appendFormat:@"  %@:// → %@\n", sc, can ? @"可打开!(未隐藏)" : @"已隐藏(canOpenURL=NO)"];
    }
    return s;
}

static NSString *chk_dyld_images(void) {
    const char *marks[] = { "decrypt_helper", "substrate", "TweakInject", "libhooker", "ellekit" };
    uint32_t cnt = _dyld_image_count();
    int hits = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        const char *n = _dyld_get_image_name(i);
        if (!n) continue;
        for (int j = 0; j < 5; j++) if (strstr(n, marks[j])) { hits++; break; }
    }
    return [NSString stringWithFormat:@"[dyld image 遍历]\n  已加载 %u 个 image, 命中注入标记 %d 个 → %@\n",
            cnt, hits, hits == 0 ? @"注入痕迹已隐藏" : @"仍可见!"];
}

static NSString *chk_antidebug(void) {
    NSMutableString *s = [NSMutableString stringWithString:@"[反调试]\n"];
    int p = ptrace(31 /*PT_DENY_ATTACH*/, 0, 0, 0);
    [s appendFormat:@"  ptrace(PT_DENY_ATTACH) → 返回 %d %@\n", p, p == 0 ? @"(空转,已绕过)" : @"(未绕过)"];
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info; size_t sz = sizeof(info);
    if (sysctl(mib, 4, &info, &sz, NULL, 0) == 0) {
        BOOL traced = (info.kp_proc.p_flag & P_TRACED) != 0;
        [s appendFormat:@"  sysctl P_TRACED → %@\n", traced ? @"被跟踪!" : @"未被跟踪(已清)"];
    }
    return s;
}

static NSString *chk_device_info(void) {
    NSMutableString *s = [NSMutableString stringWithString:@"[设备信息(改机开则为伪造值)]\n"];
    UIDevice *d = [UIDevice currentDevice];
    [s appendFormat:@"  UIDevice.systemVersion = %@\n", d.systemVersion];
    [s appendFormat:@"  UIDevice.name = %@\n", d.name];
    [s appendFormat:@"  IDFV = %@\n", d.identifierForVendor.UUIDString];
    char m[64] = {0}; size_t ml = sizeof(m);
    if (sysctlbyname("hw.machine", m, &ml, NULL, 0) == 0) [s appendFormat:@"  sysctl hw.machine = %s\n", m];
    struct utsname un; if (uname(&un) == 0) [s appendFormat:@"  uname.machine = %s\n", un.machine];
    NSUUID *idfa = [[ASIdentifierManager sharedManager] advertisingIdentifier];
    [s appendFormat:@"  IDFA = %@\n", idfa.UUIDString];
    return s;
}

// ==================== 测试台 VC ====================
@interface TestVC : UIViewController
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) NSMutableDictionary<NSString *, UIButton *> *btnMap;
@property (nonatomic, strong) NSMutableArray<UIScrollView *> *tabScrolls;
@property (nonatomic, strong) UISegmentedControl *seg;
@property (nonatomic, strong) UITextView *checkOut;
- (BOOL)triggerByKey:(NSString *)key;
@end

@implementation TestVC
- (void)viewDidLoad {
    [super viewDidLoad];
    self.btnMap = [NSMutableDictionary dictionary];
    self.tabScrolls = [NSMutableArray array];
    self.view.backgroundColor = [UIColor colorWithRed:0.07 green:0.09 blue:0.13 alpha:1.0];

    UILabel *title = [UILabel new];
    title.text = @"IOSDecryptHub 测试台";
    title.font = [UIFont systemFontOfSize:21 weight:UIFontWeightBold];
    title.textColor = [UIColor whiteColor];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:title];

    self.status = [UILabel new];
    self.status.text = @"选 tab, 点按钮触发对应系统调用, 看悬浮窗计数 / Web 面板";
    self.status.font = [UIFont systemFontOfSize:12];
    self.status.numberOfLines = 0;
    self.status.textColor = [UIColor colorWithWhite:0.6 alpha:1.0];
    self.status.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.status];

    self.seg = [[UISegmentedControl alloc] initWithItems:@[@"加解密", @"系统", @"伪装自检"]];
    self.seg.selectedSegmentIndex = 0;
    self.seg.translatesAutoresizingMaskIntoConstraints = NO;
    [self.seg addTarget:self action:@selector(onSeg:) forControlEvents:UIControlEventValueChanged];
    [self.view addSubview:self.seg];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [title.topAnchor      constraintEqualToAnchor:g.topAnchor constant:12],
        [title.leadingAnchor  constraintEqualToAnchor:g.leadingAnchor constant:16],
        [title.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [self.status.topAnchor      constraintEqualToAnchor:title.bottomAnchor constant:6],
        [self.status.leadingAnchor  constraintEqualToAnchor:g.leadingAnchor constant:16],
        [self.status.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [self.seg.topAnchor      constraintEqualToAnchor:self.status.bottomAnchor constant:10],
        [self.seg.leadingAnchor  constraintEqualToAnchor:g.leadingAnchor constant:16],
        [self.seg.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
    ]];

    UIColor *green  = [UIColor colorWithRed:0.34 green:0.83 blue:0.39 alpha:1.0];
    UIColor *blue   = [UIColor colorWithRed:0.35 green:0.65 blue:1.00 alpha:1.0];
    UIColor *orange = [UIColor colorWithRed:0.94 green:0.64 blue:0.36 alpha:1.0];
    UIColor *purple = [UIColor colorWithRed:0.82 green:0.66 blue:1.00 alpha:1.0];
    UIColor *mint   = [UIColor colorWithRed:0.36 green:0.92 blue:0.70 alpha:1.0];
    UIColor *red    = [UIColor colorWithRed:0.95 green:0.45 blue:0.45 alpha:1.0];

    // --- tab 0: 加解密 ---
    UIStackView *t0 = [self addTabStack];
    [self addGroup:t0 title:@"摘要" color:green buttons:@[@"MD5",@"SHA1",@"SHA256",@"SHA512"]
              sels:@[@"onMD5",@"onSHA1",@"onSHA256",@"onSHA512"] keys:@[@"md5",@"sha1",@"sha256",@"sha512"]];
    [self addGroup:t0 title:@"HMAC" color:blue buttons:@[@"HMAC-SHA256"] sels:@[@"onHMAC"] keys:@[@"hmac"]];
    [self addGroup:t0 title:@"对称加密" color:orange buttons:@[@"AES-CBC",@"3DES",@"DES",@"RC4"]
              sels:@[@"onAES",@"on3DES",@"onDES",@"onRC4"] keys:@[@"aes",@"3des",@"des",@"rc4"]];
    [self addGroup:t0 title:@"非对称" color:purple buttons:@[@"RSA 签名",@"RSA 加密"]
              sels:@[@"onRSASign",@"onRSAEnc"] keys:@[@"rsasign",@"rsaenc"]];
    [self addGroup:t0 title:@"密钥派生" color:mint buttons:@[@"PBKDF2"] sels:@[@"onPBKDF"] keys:@[@"pbkdf"]];
    [self addGroup:t0 title:@"压测 / 综合" color:red buttons:@[@"128KB 大数据",@"全部跑一遍",@"打开日志"]
              sels:@[@"onBig",@"onAll",@"onLog"] keys:@[@"big",@"all",@"log"]];

    // --- tab 1: 系统(文件 + 模块加载) ---
    UIStackView *t1 = [self addTabStack];
    [self addGroup:t1 title:@"文件操作" color:orange buttons:@[@"写文件",@"读文件",@"删除",@"重命名"]
              sels:@[@"onFWrite",@"onFRead",@"onFDel",@"onFRename"] keys:@[@"fwrite",@"fread",@"fdel",@"frename"]];
    [self addGroup:t1 title:@"动态库" color:purple buttons:@[@"dlopen 模块", @"dlsym 符号"]
              sels:@[@"onDlopen",@"onDlsym"] keys:@[@"dlopen",@"dlsym"]];

    // --- tab 2: 伪装自检(验证越狱绕过 / 改机 / 注入隐藏是否生效) ---
    UIStackView *t2 = [self addTabStack];
    [self addGroup:t2 title:@"越狱绕过" color:green buttons:@[@"越狱文件探测",@"URL Scheme",@"dyld 遍历"]
              sels:@[@"onChkJB",@"onChkURL",@"onChkDyld"] keys:@[@"chkjb",@"chkurl",@"chkdyld"]];
    [self addGroup:t2 title:@"反调试 / 改机" color:orange buttons:@[@"反调试",@"设备信息",@"全部自检"]
              sels:@[@"onChkAnti",@"onChkDevice",@"onChkAll"] keys:@[@"chkanti",@"chkdevice",@"chkall"]];
    UILabel *rl = [UILabel new];
    rl.text = @"自检结果(这些调用也会被 dylib 观测并落日志):";
    rl.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    rl.textColor = [UIColor colorWithWhite:0.5 alpha:1.0];
    [t2 addArrangedSubview:rl];
    self.checkOut = [UITextView new];
    self.checkOut.editable = NO;
    self.checkOut.backgroundColor = [UIColor colorWithRed:0.05 green:0.06 blue:0.09 alpha:1.0];
    self.checkOut.textColor = [UIColor colorWithRed:0.80 green:0.86 blue:0.90 alpha:1.0];
    self.checkOut.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.checkOut.layer.cornerRadius = 8;
    self.checkOut.text = @"点上面按钮运行自检…\n";
    [self.checkOut.heightAnchor constraintEqualToConstant:300].active = YES;
    [t2 addArrangedSubview:self.checkOut];

    self.tabScrolls[0].hidden = NO;   // 默认显示加解密

    __weak typeof(self) ws = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSString *u = dh_real_url();
        gUrlHint = u ?: @"";
        if (u) ws.status.text = [NSString stringWithFormat:@"选 tab 点按钮触发, 看悬浮窗 / 浏览器 %@", u];
    });
    // 启动后发一次网络请求, 触发网络抓包 hook (即便无外网, resume 已在请求发出前被 swizzle 捕获)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ do_network(); });
    if ([[NSProcessInfo processInfo].environment[@"DH_AUTOLOG"] isEqualToString:@"1"]) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.3 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [ws triggerByKey:@"log"]; });
    }
    // 截图/自动化: DH_AUTOTEST=1 启动后自动触发各类调用(免 simctl openurl 确认框)
    if ([[NSProcessInfo processInfo].environment[@"DH_AUTOTEST"] isEqualToString:@"1"]) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            for (NSString *k in @[@"md5",@"sha256",@"hmac",@"aes",@"3des",@"rsasign",@"pbkdf",
                                  @"fwrite",@"fread",@"fdel",@"frename",@"dlopen",@"dlsym",
                                  @"chkjb",@"chkurl",@"chkdyld",@"chkanti",@"chkdevice"])
                [ws triggerByKey:k];
        });
    }
}

- (UIStackView *)addTabStack {
    UIScrollView *sv = [UIScrollView new];
    sv.translatesAutoresizingMaskIntoConstraints = NO;
    sv.hidden = YES;
    [self.view addSubview:sv];
    UIStackView *stack = [UIStackView new];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 10;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [sv addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [sv.topAnchor      constraintEqualToAnchor:self.seg.bottomAnchor constant:12],
        [sv.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor],
        [sv.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [sv.bottomAnchor   constraintEqualToAnchor:self.view.bottomAnchor],
        [stack.topAnchor      constraintEqualToAnchor:sv.topAnchor],
        [stack.leadingAnchor  constraintEqualToAnchor:sv.leadingAnchor constant:16],
        [stack.trailingAnchor constraintEqualToAnchor:sv.trailingAnchor constant:-16],
        [stack.bottomAnchor   constraintEqualToAnchor:sv.bottomAnchor constant:-16],
        [stack.widthAnchor    constraintEqualToAnchor:sv.widthAnchor constant:-32],
    ]];
    [self.tabScrolls addObject:sv];
    return stack;
}

- (void)onSeg:(UISegmentedControl *)s {
    for (NSUInteger i = 0; i < self.tabScrolls.count; i++)
        self.tabScrolls[i].hidden = (i != (NSUInteger)s.selectedSegmentIndex);
}

- (void)addGroup:(UIStackView *)parent title:(NSString *)t color:(UIColor *)c
         buttons:(NSArray<NSString *> *)titles sels:(NSArray<NSString *> *)sels
            keys:(NSArray<NSString *> *)keys {
    UILabel *gl = [UILabel new];
    gl.text = t;
    gl.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    gl.textColor = [UIColor colorWithWhite:0.5 alpha:1.0];
    [parent addArrangedSubview:gl];
    UIStackView *row = nil;
    for (NSUInteger i = 0; i < titles.count; i++) {
        if (i % 2 == 0) {
            row = [UIStackView new];
            row.axis = UILayoutConstraintAxisHorizontal;
            row.spacing = 10;
            row.distribution = UIStackViewDistributionFillEqually;
            [parent addArrangedSubview:row];
        }
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        [b setTitle:titles[i] forState:UIControlStateNormal];
        [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
        b.backgroundColor = [c colorWithAlphaComponent:0.22];
        b.layer.cornerRadius = 10;
        b.layer.borderWidth = 1.0;
        b.layer.borderColor = [c colorWithAlphaComponent:0.6].CGColor;
        [b.heightAnchor constraintEqualToConstant:46].active = YES;
        [b addTarget:self action:NSSelectorFromString(sels[i]) forControlEvents:UIControlEventTouchUpInside];
        [row addArrangedSubview:b];
        self.btnMap[keys[i]] = b;
    }
    if (titles.count % 2 == 1) [row addArrangedSubview:[UIView new]];  // 单数补占位, 末按钮不撑满
}

- (BOOL)triggerByKey:(NSString *)key {
    UIButton *b = self.btnMap[key.lowercaseString];
    if (!b) return NO;
    [b sendActionsForControlEvents:UIControlEventTouchUpInside];
    return YES;
}

- (void)flash:(NSString *)name {
    NSString *u = gUrlHint.length ? [@" / 浏览器 " stringByAppendingString:gUrlHint] : @"";
    self.status.text = [NSString stringWithFormat:@"已触发 %@, 看悬浮窗计数%@", name, u];
    self.status.textColor = [UIColor colorWithRed:0.36 green:0.92 blue:0.70 alpha:1.0];
}

// 加解密
- (void)onMD5    { do_digest(0); [self flash:@"MD5"]; }
- (void)onSHA1   { do_digest(1); [self flash:@"SHA1"]; }
- (void)onSHA256 { do_digest(2); [self flash:@"SHA256"]; }
- (void)onSHA512 { do_digest(3); [self flash:@"SHA512"]; }
- (void)onHMAC   { do_hmac();    [self flash:@"HMAC-SHA256"]; }
- (void)onAES    { do_sym(kCCAlgorithmAES, 16, 16);  [self flash:@"AES-128-CBC"]; }
- (void)on3DES   { do_sym(kCCAlgorithm3DES, 24, 8);  [self flash:@"3DES"]; }
- (void)onDES    { do_sym(kCCAlgorithmDES, 8, 8);    [self flash:@"DES"]; }
- (void)onRC4    { do_rc4();      [self flash:@"RC4"]; }
- (void)onRSASign {
    [self flash:@"RSA 签名 (首次生成密钥…)"];
    dispatch_async(dispatch_get_global_queue(0, 0), ^{ do_rsa_sign(); dispatch_async(dispatch_get_main_queue(), ^{ [self flash:@"RSA 签名"]; }); });
}
- (void)onRSAEnc {
    [self flash:@"RSA 加密 (首次生成密钥…)"];
    dispatch_async(dispatch_get_global_queue(0, 0), ^{ do_rsa_enc(); dispatch_async(dispatch_get_main_queue(), ^{ [self flash:@"RSA 加密"]; }); });
}
- (void)onPBKDF  { do_pbkdf();    [self flash:@"PBKDF2-HMAC-SHA256"]; }
- (void)onBig    { do_bigdata();  [self flash:@"128KB 大数据 AES"]; }
- (void)onAll {
    do_digest(0); do_digest(1); do_digest(2); do_digest(3);
    do_hmac(); do_sym(kCCAlgorithmAES, 16, 16); do_sym(kCCAlgorithm3DES, 24, 8);
    do_sym(kCCAlgorithmDES, 8, 8); do_rc4(); do_pbkdf();
    dispatch_async(dispatch_get_global_queue(0, 0), ^{ do_rsa_sign(); do_rsa_enc(); });
    [self flash:@"全部算法"];
}
- (void)onLog {
    Class c = NSClassFromString(@"DHLogViewer");
    if (c && [c respondsToSelector:@selector(presentFromFloating)]) [c performSelector:@selector(presentFromFloating)];
}
// 文件
- (void)onFWrite   { do_file_write();  [self flash:@"写文件"]; }
- (void)onFRead    { do_file_read();   [self flash:@"读文件"]; }
- (void)onFDel     { do_file_delete(); [self flash:@"删除文件"]; }
- (void)onFRename  { do_file_rename(); [self flash:@"重命名"]; }
// 系统
- (void)onDlopen   { do_dlopen();      [self flash:@"dlopen 模块"]; }
- (void)onDlsym    { do_dlsym();       [self flash:@"dlsym 符号"]; }
// 伪装自检
- (void)appendCheck:(NSString *)text {
    self.checkOut.text = [self.checkOut.text stringByAppendingString:[text stringByAppendingString:@"\n"]];
    NSRange end = NSMakeRange(self.checkOut.text.length, 0);
    [self.checkOut scrollRangeToVisible:end];
}
- (void)onChkJB     { [self appendCheck:chk_jailbreak_files()]; [self flash:@"越狱文件探测"]; }
- (void)onChkURL    { [self appendCheck:chk_url_schemes()];     [self flash:@"URL Scheme 探测"]; }
- (void)onChkDyld   { [self appendCheck:chk_dyld_images()];     [self flash:@"dyld 遍历"]; }
- (void)onChkAnti   { [self appendCheck:chk_antidebug()];       [self flash:@"反调试自检"]; }
- (void)onChkDevice { [self appendCheck:chk_device_info()];     [self flash:@"设备信息"]; }
- (void)onChkAll {
    self.checkOut.text = @"";
    [self appendCheck:chk_jailbreak_files()];
    [self appendCheck:chk_url_schemes()];
    [self appendCheck:chk_dyld_images()];
    [self appendCheck:chk_antidebug()];
    [self appendCheck:chk_device_info()];
    [self flash:@"全部自检完成"];
}
@end

// ==================== Scene / App ====================
@interface SceneDelegate : UIResponder <UIWindowSceneDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation SceneDelegate
- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session
      options:(UISceneConnectionOptions *)connectionOptions {
    UIWindowScene *ws = (UIWindowScene *)scene;
    self.window = [[UIWindow alloc] initWithWindowScene:ws];
    self.window.rootViewController = [TestVC new];
    [self.window makeKeyAndVisible];
    if (connectionOptions.URLContexts.count) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self scene:scene openURLContexts:connectionOptions.URLContexts]; });
    }
}
- (void)scene:(UIScene *)scene openURLContexts:(NSSet<UIOpenURLContext *> *)URLContexts {
    TestVC *vc = (TestVC *)self.window.rootViewController;
    if (![vc isKindOfClass:[TestVC class]]) return;
    for (UIOpenURLContext *ctx in URLContexts) {
        NSString *key = ctx.URL.host ?: [ctx.URL.path stringByReplacingOccurrencesOfString:@"/" withString:@""];
        [vc triggerByKey:key];
    }
}
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions { return YES; }
- (UISceneConfiguration *)application:(UIApplication *)application
        configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession
        options:(UISceneConnectionOptions *)options {
    UISceneConfiguration *cfg = [[UISceneConfiguration alloc] initWithName:@"Default" sessionRole:connectingSceneSession.role];
    cfg.delegateClass = [SceneDelegate class];
    return cfg;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class])); }
}
