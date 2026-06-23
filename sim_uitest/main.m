// sim_uitest/main.m — 交互式加密算法测试台
// 每个按钮单独触发一类算法(而非启动一次性全跑), 便于逐个观察 hook 效果。
// 触发后看右上角「解密助手」悬浮窗计数, 或用浏览器打开悬浮窗显示的地址(端口自动分配)。
//
// 自动化测试通道: 注册 URL scheme "dhtest", 用
//   xcrun simctl openurl <dev> dhtest://md5
// 会通过 sendActionsForControlEvents: 模拟点击对应按钮(完整 UIKit 事件分发)。

#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>
#import <dlfcn.h>

// 运行时从注入的 dylib 取真实服务地址(端口会在 8088..8108 间自动顺延), 避免写死端口
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

// ==================== 算法触发函数 ====================
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
    CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0, key, sizeof(key), NULL,
            m, strlen(m), out, sizeof(out), &mv);
}
static SecKeyRef gRSA = NULL;
static SecKeyRef rsa_key(void) {
    if (gRSA) return gRSA;
    NSDictionary *p = @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                         (id)kSecAttrKeySizeInBits: @2048 };
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

// ==================== 测试台 VC ====================
@interface TestVC : UIViewController
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) NSMutableDictionary<NSString *, UIButton *> *btnMap;
- (BOOL)triggerByKey:(NSString *)key;
@end

@implementation TestVC
- (void)viewDidLoad {
    [super viewDidLoad];
    self.btnMap = [NSMutableDictionary dictionary];
    self.view.backgroundColor = [UIColor colorWithRed:0.07 green:0.09 blue:0.13 alpha:1.0];

    UIScrollView *sv = [UIScrollView new];
    sv.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:sv];
    UIStackView *stack = [UIStackView new];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 10;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [sv addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [sv.topAnchor      constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [sv.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor],
        [sv.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [sv.bottomAnchor   constraintEqualToAnchor:self.view.bottomAnchor],
        [stack.topAnchor      constraintEqualToAnchor:sv.topAnchor constant:16],
        [stack.leadingAnchor  constraintEqualToAnchor:sv.leadingAnchor constant:16],
        [stack.trailingAnchor constraintEqualToAnchor:sv.trailingAnchor constant:-16],
        [stack.bottomAnchor   constraintEqualToAnchor:sv.bottomAnchor constant:-16],
        [stack.widthAnchor    constraintEqualToAnchor:sv.widthAnchor constant:-32],
    ]];

    UILabel *title = [UILabel new];
    title.text = @"加密算法测试台";
    title.font = [UIFont systemFontOfSize:22 weight:UIFontWeightBold];
    title.textColor = [UIColor whiteColor];
    [stack addArrangedSubview:title];

    self.status = [UILabel new];
    self.status.text = @"点按钮触发对应算法, 看右上角悬浮窗计数";
    self.status.font = [UIFont systemFontOfSize:13];
    self.status.numberOfLines = 0;
    self.status.textColor = [UIColor colorWithWhite:0.6 alpha:1.0];
    [stack addArrangedSubview:self.status];

    UIColor *green  = [UIColor colorWithRed:0.34 green:0.83 blue:0.39 alpha:1.0];
    UIColor *blue   = [UIColor colorWithRed:0.35 green:0.65 blue:1.00 alpha:1.0];
    UIColor *orange = [UIColor colorWithRed:0.94 green:0.64 blue:0.36 alpha:1.0];
    UIColor *purple = [UIColor colorWithRed:0.82 green:0.66 blue:1.00 alpha:1.0];
    UIColor *mint   = [UIColor colorWithRed:0.36 green:0.92 blue:0.70 alpha:1.0];
    UIColor *red    = [UIColor colorWithRed:0.95 green:0.45 blue:0.45 alpha:1.0];

    [self addGroup:stack title:@"摘要" color:green
           buttons:@[@"MD5",@"SHA1",@"SHA256",@"SHA512"]
              sels:@[@"onMD5",@"onSHA1",@"onSHA256",@"onSHA512"]
              keys:@[@"md5",@"sha1",@"sha256",@"sha512"]];
    [self addGroup:stack title:@"HMAC" color:blue
           buttons:@[@"HMAC-SHA256"] sels:@[@"onHMAC"] keys:@[@"hmac"]];
    [self addGroup:stack title:@"对称加密" color:orange
           buttons:@[@"AES-CBC",@"3DES",@"DES",@"RC4"]
              sels:@[@"onAES",@"on3DES",@"onDES",@"onRC4"]
              keys:@[@"aes",@"3des",@"des",@"rc4"]];
    [self addGroup:stack title:@"非对称" color:purple
           buttons:@[@"RSA 签名",@"RSA 加密"] sels:@[@"onRSASign",@"onRSAEnc"]
              keys:@[@"rsasign",@"rsaenc"]];
    [self addGroup:stack title:@"密钥派生" color:mint
           buttons:@[@"PBKDF2"] sels:@[@"onPBKDF"] keys:@[@"pbkdf"]];
    [self addGroup:stack title:@"压测 / 综合" color:red
           buttons:@[@"128KB 大数据",@"全部跑一遍",@"打开日志"]
              sels:@[@"onBig",@"onAll",@"onLog"]
              keys:@[@"big",@"all",@"log"]];

    // dylib 启动 HTTP 服务后异步读取真实地址(含实际端口)填入提示
    __weak typeof(self) ws = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        NSString *u = dh_real_url();
        gUrlHint = u ?: @"";
        if (u) ws.status.text = [NSString stringWithFormat:@"点按钮触发对应算法, 看右上角悬浮窗计数 / 浏览器 %@", u];
    });

    // 截图/自动化: 设 DH_AUTOLOG=1 启动后自动打开日志查看器(走 triggerByKey, 免去 simctl openurl 的系统确认框)
    if ([[NSProcessInfo processInfo].environment[@"DH_AUTOLOG"] isEqualToString:@"1"]) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.3 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [ws triggerByKey:@"log"]; });
    }
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
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        do_rsa_sign();
        dispatch_async(dispatch_get_main_queue(), ^{ [self flash:@"RSA 签名"]; });
    });
}
- (void)onRSAEnc {
    [self flash:@"RSA 加密 (首次生成密钥…)"];
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        do_rsa_enc();
        dispatch_async(dispatch_get_main_queue(), ^{ [self flash:@"RSA 加密"]; });
    });
}
- (void)onPBKDF  { do_pbkdf();    [self flash:@"PBKDF2-HMAC-SHA256"]; }
- (void)onBig    { do_bigdata();  [self flash:@"128KB 大数据 AES"]; }
- (void)onAll {
    do_digest(0); do_digest(1); do_digest(2); do_digest(3);
    do_hmac();
    do_sym(kCCAlgorithmAES, 16, 16); do_sym(kCCAlgorithm3DES, 24, 8);
    do_sym(kCCAlgorithmDES, 8, 8); do_rc4();
    do_pbkdf();
    dispatch_async(dispatch_get_global_queue(0, 0), ^{ do_rsa_sign(); do_rsa_enc(); });
    [self flash:@"全部算法"];
}
- (void)onLog {
    Class c = NSClassFromString(@"DHLogViewer");
    if (c && [c respondsToSelector:@selector(presentFromFloating)]) {
        [c performSelector:@selector(presentFromFloating)];
    }
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
    // 冷启动经 dhtest:// 唤起时 URL 在 connectionOptions 里, 补触发(否则冷启动不响应)
    if (connectionOptions.URLContexts.count) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self scene:scene openURLContexts:connectionOptions.URLContexts];
        });
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
- (BOOL)application:(UIApplication *)application
        didFinishLaunchingWithOptions:(NSDictionary *)launchOptions { return YES; }
- (UISceneConfiguration *)application:(UIApplication *)application
        configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession
        options:(UISceneConnectionOptions *)options {
    UISceneConfiguration *cfg = [[UISceneConfiguration alloc] initWithName:@"Default"
                                                              sessionRole:connectingSceneSession.role];
    cfg.delegateClass = [SceneDelegate class];
    return cfg;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
