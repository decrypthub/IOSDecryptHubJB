// ui_float.m
// 悬浮窗 - 只显示状态(各算法计数)和控制按钮(打开日志/清空/暂停/缩小).
// 严格不显示任何明文 / 密文 / 摘要 - 那些都在 ui_logview.
//
// UIKit 隔离: macOS 纯 target 没有 UIKit, 整个文件编译为空, 提供 no-op stub.
// iOS / Mac Catalyst / iOS Simulator 都有 UIKit, 正常走.

#import "ui_float.h"

#if __has_include(<UIKit/UIKit.h>)

#import <UIKit/UIKit.h>
#import "ui_logview.h"
#import "log_store.h"
#import "http_server.h"
#import "dh_health.h"

#define DH_ACCENT [UIColor colorWithRed:0.36 green:0.92 blue:0.70 alpha:1.0]

@interface DHFloatingController : NSObject
@property (nonatomic, strong) UIWindow    *window;
@property (nonatomic, strong) UIView      *bar;
@property (nonatomic, strong) UILabel     *titleLabel;
@property (nonatomic, strong) UIButton    *minBtn;
@property (nonatomic, strong) UIImageView *collapsedIcon;   // 缩小态的圆形小图标
@property (nonatomic, strong) UILabel     *statsLabel;
@property (nonatomic, strong) UILabel     *urlLabel;
@property (nonatomic, strong) UIButton    *openBtn;
@property (nonatomic, strong) UIButton    *clearBtn;
@property (nonatomic, strong) UIButton    *pauseBtn;
@property (nonatomic, strong) NSTimer     *statsTimer;
@property (nonatomic, assign) BOOL         collapsed;
@property (nonatomic, assign) CGRect       expandedFrame;
@end

static DHFloatingController *gFloat = nil;

@implementation DHFloatingController

- (instancetype)init {
    if ((self = [super init])) {
        [self build];
    }
    return self;
}

- (UIWindow *)mostUsableWindowScene {
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]
                && s.activationState == UISceneActivationStateForegroundActive) {
                return [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)s];
            }
        }
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) {
                return [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)s];
            }
        }
    }
    return [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
}

- (void)build {
    CGRect screen = [UIScreen mainScreen].bounds;
    CGFloat W = 252, H = 188;
    // 初始贴右上, 顶部避开灵动岛/刘海 (保守安全值, 拖动后随用户)
    CGRect frame = CGRectMake(screen.size.width - W - 12, 64, W, H);
    self.expandedFrame = frame;

    UIWindow *w = [self mostUsableWindowScene];
    w.frame = frame;
    w.windowLevel = UIWindowLevelAlert + 1000;
    w.backgroundColor = [UIColor clearColor];
    w.layer.cornerRadius = 18;
    w.layer.masksToBounds = YES;
    w.rootViewController = [UIViewController new];
    w.rootViewController.view.backgroundColor = [UIColor clearColor];
    self.window = w;
    UIView *root = w.rootViewController.view;

    // 毛玻璃背景 (UIVisualEffectView) — 现代玻璃质感
    UIVisualEffectView *glass = [[UIVisualEffectView alloc]
        initWithEffect:[UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemThinMaterialDark]];
    glass.frame = CGRectMake(0, 0, W, H);
    glass.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    glass.layer.cornerRadius = 18;
    glass.layer.masksToBounds = YES;
    glass.layer.borderWidth = 0.5;
    glass.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.20].CGColor;
    [root addSubview:glass];

    // 缩小态的圆形小图标 (SF Symbol 钥匙, 渲染可靠, 不依赖 emoji), 展开态隐藏
    UIImageView *icon = [[UIImageView alloc] initWithFrame:CGRectMake(0, 0, W, H)];
    if (@available(iOS 13.0, *)) {
        UIImageSymbolConfiguration *cfg =
            [UIImageSymbolConfiguration configurationWithPointSize:24 weight:UIImageSymbolWeightSemibold];
        icon.image = [UIImage systemImageNamed:@"key.fill" withConfiguration:cfg];
    }
    icon.tintColor = DH_ACCENT;
    icon.contentMode = UIViewContentModeCenter;
    icon.alpha = 0;
    self.collapsedIcon = icon;
    [root addSubview:icon];

    // 标题栏 (透明, 让毛玻璃透出)
    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, W, 40)];
    bar.backgroundColor = [UIColor clearColor];
    bar.userInteractionEnabled = YES;
    self.bar = bar;
    [root addSubview:bar];

    self.titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(14, 9, 170, 22)];
    self.titleLabel.text = @"IOSDecryptHub";
    self.titleLabel.textColor = DH_ACCENT;
    self.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
    [bar addSubview:self.titleLabel];

    self.minBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.minBtn.frame = CGRectMake(W - 44, 4, 40, 32);   // 44pt 触控区
    [self.minBtn setTitle:@"–" forState:UIControlStateNormal];
    [self.minBtn setTitleColor:[UIColor colorWithWhite:0.72 alpha:1.0] forState:UIControlStateNormal];
    self.minBtn.titleLabel.font = [UIFont systemFontOfSize:24 weight:UIFontWeightMedium];
    [self.minBtn addTarget:self action:@selector(toggleCollapsed) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:self.minBtn];

    // 拖动手势 + 缩小态点击展开
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(onPan:)];
    [bar addGestureRecognizer:pan];
    UITapGestureRecognizer *barTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onBarTap)];
    [bar addGestureRecognizer:barTap];
    // 缩小态整个圆形图标也可点击展开
    UITapGestureRecognizer *iconTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onBarTap)];
    icon.userInteractionEnabled = YES;
    [icon addGestureRecognizer:iconTap];

    // 统计文本
    self.statsLabel = [[UILabel alloc] initWithFrame:CGRectMake(14, 48, W - 28, 40)];
    self.statsLabel.numberOfLines = 0;
    self.statsLabel.textColor = [UIColor colorWithWhite:0.92 alpha:1.0];
    self.statsLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
    [root addSubview:self.statsLabel];

    // URL 一行: http://ip:port  (点击复制)
    self.urlLabel = [[UILabel alloc] initWithFrame:CGRectMake(14, 92, W - 28, 40)];
    self.urlLabel.numberOfLines = 2;
    self.urlLabel.textColor = [UIColor colorWithRed:0.45 green:0.85 blue:1.0 alpha:1.0];
    self.urlLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.urlLabel.adjustsFontSizeToFitWidth = YES;
    self.urlLabel.minimumScaleFactor = 0.7;
    self.urlLabel.userInteractionEnabled = YES;
    self.urlLabel.text = @"(本地服务启动中…)";
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self
                                                                          action:@selector(onCopyURL)];
    [self.urlLabel addGestureRecognizer:tap];
    [root addSubview:self.urlLabel];

    // 操作按钮区 (44pt 触控高度, 玻璃按钮)
    CGFloat by = 138, bw = 70, bh = 40, bx = 12, gap = 9;
    self.openBtn  = [self makeButton:@"日志" color:[UIColor colorWithRed:0.36 green:0.65 blue:1.00 alpha:1.0]
                               frame:CGRectMake(bx, by, bw, bh) action:@selector(onOpenLog)];
    self.pauseBtn = [self makeButton:@"暂停" color:[UIColor colorWithRed:0.95 green:0.75 blue:0.30 alpha:1.0]
                               frame:CGRectMake(bx + (bw+gap), by, bw, bh) action:@selector(onTogglePause)];
    self.clearBtn = [self makeButton:@"清空" color:[UIColor colorWithRed:0.95 green:0.45 blue:0.45 alpha:1.0]
                               frame:CGRectMake(bx + 2*(bw+gap), by, bw, bh) action:@selector(onClear)];
    [root addSubview:self.openBtn];
    [root addSubview:self.pauseBtn];
    [root addSubview:self.clearBtn];

    w.hidden = NO;

    // 定时刷新统计 (1 秒) — block + weak self, 避免 retain cycle; 缩小态不刷新
    __weak typeof(self) weakSelf = self;
    self.statsTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *t) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) { [t invalidate]; return; }
        if (strongSelf.collapsed) return;
        [strongSelf refreshStats];
    }];
    [self refreshStats];
}

- (UIButton *)makeButton:(NSString *)t color:(UIColor *)c frame:(CGRect)f action:(SEL)sel {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = f;
    [b setTitle:t forState:UIControlStateNormal];
    [b setTitleColor:[UIColor colorWithWhite:0.96 alpha:1.0] forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
    // 玻璃按钮: 半透明语义色底 + 同色描边 + 白字
    b.backgroundColor = [c colorWithAlphaComponent:0.22];
    b.layer.cornerRadius = 11;
    b.layer.borderWidth = 1.0;
    b.layer.borderColor = [c colorWithAlphaComponent:0.55].CGColor;
    [b addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (void)refreshStats {
    DHLogStore *s = [DHLogStore shared];
    NSUInteger d = [s countForCategory:DHCategoryDigest];
    NSUInteger h = [s countForCategory:DHCategoryHMAC];
    NSUInteger sym = [s countForCategory:DHCategorySymmetric];
    NSUInteger asym = [s countForCategory:DHCategoryAsymmetric];
    NSString *state = s.paused ? @"已暂停" : @"运行中";
    self.statsLabel.text = [NSString stringWithFormat:
        @"%@   总 %lu   摘要 %lu\nHMAC %lu  对称 %lu  RSA %lu",
        state, (unsigned long)[s totalCount],
        (unsigned long)d, (unsigned long)h, (unsigned long)sym, (unsigned long)asym];

    // fail-loud: 把健康状态显示出来 —— 服务失败/hook未挂上/落盘失败都用红字明示,
    // 而不是恒显"启动中…"假装一切正常.
    const char *hc = dh_health_summary();
    NSString *health = (hc && hc[0]) ? [NSString stringWithUTF8String:hc] : @"";
    UIColor *blue = [UIColor colorWithRed:0.45 green:0.85 blue:1.0 alpha:1.0];
    UIColor *red  = [UIColor colorWithRed:0.98 green:0.45 blue:0.42 alpha:1.0];

    uint16_t port = dh_http_port();
    if (dh_health_http_failed()) {
        self.urlLabel.textColor = red;
        self.urlLabel.text = [NSString stringWithFormat:@"服务失败\n%@", health.length ? health : @"端口被占用"];
    } else if (port > 0) {
        NSString *url = dh_http_url();
        if (dh_health_local_only()) url = [url stringByAppendingString:@" (仅本地)"];
        if (health.length) {
            self.urlLabel.textColor = red;
            self.urlLabel.text = [NSString stringWithFormat:@"%@\n⚠ %@", url, health];
        } else {
            self.urlLabel.textColor = blue;
            self.urlLabel.text = [NSString stringWithFormat:@"%@\n(点这里复制)", url];
        }
    } else {
        self.urlLabel.textColor = blue;
        self.urlLabel.text = @"(本地服务启动中…)";
    }
}

- (void)onCopyURL {
    NSString *u = dh_http_url();
    if (!u || ![u hasPrefix:@"http"]) return;
    [UIPasteboard generalPasteboard].string = u;
    NSString *original = self.urlLabel.text;
    self.urlLabel.text = @"已复制到剪贴板";
    self.urlLabel.textColor = DH_ACCENT;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        self.urlLabel.textColor = [UIColor colorWithRed:0.45 green:0.85 blue:1.0 alpha:1.0];
        if ([self.urlLabel.text isEqualToString:@"已复制到剪贴板"]) self.urlLabel.text = original;
    });
}

- (void)onPan:(UIPanGestureRecognizer *)g {
    CGPoint t = [g translationInView:g.view.window];
    if (g.state == UIGestureRecognizerStateChanged) {
        CGRect f = self.window.frame;
        f.origin.x += t.x;
        f.origin.y += t.y;
        CGRect scr = [UIScreen mainScreen].bounds;
        f.origin.x = MAX(0, MIN(scr.size.width  - f.size.width,  f.origin.x));
        f.origin.y = MAX(0, MIN(scr.size.height - f.size.height, f.origin.y));
        self.window.frame = f;
        if (!self.collapsed) self.expandedFrame = f;
        [g setTranslation:CGPointZero inView:g.view.window];
    }
}

- (void)toggleCollapsed {
    self.collapsed = !self.collapsed;
    CGRect target; CGFloat radius;
    if (self.collapsed) {
        // 缩小成一个圆形小图标 (54x54)
        CGFloat D = 54;
        target = CGRectMake(self.window.frame.origin.x, self.window.frame.origin.y, D, D);
        radius = D / 2;
    } else {
        target = self.expandedFrame;
        target.origin.x = self.window.frame.origin.x;
        target.origin.y = self.window.frame.origin.y;
        radius = 18;
    }
    BOOL col = self.collapsed;
    [UIView animateWithDuration:0.30 delay:0 usingSpringWithDamping:0.82 initialSpringVelocity:0
                        options:UIViewAnimationOptionCurveEaseInOut animations:^{
        self.window.frame = target;
        self.window.layer.cornerRadius = radius;
        self.collapsedIcon.frame = CGRectMake(0, 0, target.size.width, target.size.height);
        self.collapsedIcon.alpha = col ? 1 : 0;
        self.titleLabel.alpha = col ? 0 : 1;
        self.minBtn.alpha     = col ? 0 : 1;
        self.statsLabel.alpha = col ? 0 : 1;
        self.urlLabel.alpha   = col ? 0 : 1;
        self.openBtn.alpha    = col ? 0 : 1;
        self.pauseBtn.alpha   = col ? 0 : 1;
        self.clearBtn.alpha   = col ? 0 : 1;
    } completion:nil];
}

- (void)onBarTap {
    // 缩小态点击(标题栏或圆形图标)展开; 展开态点击不缩小, 避免误触(缩小用「–」按钮)
    if (self.collapsed) [self toggleCollapsed];
}

- (void)onOpenLog {
    [DHLogViewer presentFromFloating];
}

- (void)onTogglePause {
    DHLogStore *s = [DHLogStore shared];
    s.paused = !s.paused;
    [self.pauseBtn setTitle:s.paused ? @"恢复" : @"暂停" forState:UIControlStateNormal];
    [self refreshStats];
}

- (void)onClear {
    // 二次确认: 文字变 "再点一次", 3 秒内再点才真正清空, 否则恢复
    if ([self.clearBtn.titleLabel.text isEqualToString:@"再点一次"]) {
        [[DHLogStore shared] clearAll];
        [self.clearBtn setTitle:@"清空" forState:UIControlStateNormal];
        [self refreshStats];
        return;
    }
    [self.clearBtn setTitle:@"再点一次" forState:UIControlStateNormal];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if ([self.clearBtn.titleLabel.text isEqualToString:@"再点一次"]) {
            [self.clearBtn setTitle:@"清空" forState:UIControlStateNormal];
        }
    });
}

@end

static BOOL dh_scene_ready(void) {
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]
                && s.activationState == UISceneActivationStateForegroundActive) {
                return YES;
            }
        }
        return NO;
    }
    return YES;
}

// 读取宿主被注入 App 的图标 -> PNG (best-effort): 优先 CFBundleIcons 里最大的一张,
// 退化尝试常见 AppIcon 名。imageNamed 能从 Assets.car 读出真机图标。
NSData *dh_host_app_icon_png(void) {
    UIImage *icon = nil;
    NSBundle *mb = [NSBundle mainBundle];
    NSDictionary *icons = [mb objectForInfoDictionaryKey:@"CFBundleIcons"];
    NSArray *files = icons[@"CFBundlePrimaryIcon"][@"CFBundleIconFiles"];
    for (NSString *n in [files reverseObjectEnumerator]) {
        UIImage *i = [UIImage imageNamed:n];
        if (i) { icon = i; break; }
    }
    if (!icon) {
        for (NSString *n in @[@"AppIcon60x60", @"AppIcon", @"Icon-60", @"Icon", @"icon"]) {
            UIImage *i = [UIImage imageNamed:n];
            if (i) { icon = i; break; }
        }
    }
    if (!icon) return nil;
    NSData *png = UIImagePNGRepresentation(icon);
    if (!png || png.length > 200 * 1024) return nil;
    return png;
}

void dh_ui_install_floating(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gFloat) return;
        if (!dh_scene_ready()) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ dh_ui_install_floating(); });
            return;
        }
        gFloat = [[DHFloatingController alloc] init];
    });
}

#else  // !__has_include(<UIKit/UIKit.h>)

// 纯 macOS target 下没有 UIKit, 提供空 stub - 浏览器看 web 面板就够了.
void dh_ui_install_floating(void) {}
NSData *dh_host_app_icon_png(void) { return nil; }

#endif
