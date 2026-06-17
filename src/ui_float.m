// ui_float.m
// 悬浮窗 - 只显示状态(各算法计数)和控制按钮(打开日志/清空/暂停/隐藏)
// 严格不显示任何明文 / 密文 / 摘要 - 那些都在 ui_logview.

#import <UIKit/UIKit.h>
#import "ui_float.h"
#import "ui_logview.h"
#import "log_store.h"
#import "http_server.h"

@interface DHFloatingController : NSObject
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UILabel  *titleLabel;
@property (nonatomic, strong) UILabel  *statsLabel;
@property (nonatomic, strong) UILabel  *urlLabel;
@property (nonatomic, strong) UIButton *openBtn;
@property (nonatomic, strong) UIButton *clearBtn;
@property (nonatomic, strong) UIButton *pauseBtn;
@property (nonatomic, strong) NSTimer  *statsTimer;
@property (nonatomic, assign) BOOL      collapsed;
@property (nonatomic, assign) CGRect    expandedFrame;
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
        // 退而求其次取任意 UIWindowScene
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
    CGFloat W = 240, H = 158;
    CGRect frame = CGRectMake(screen.size.width - W - 12, 90, W, H);
    self.expandedFrame = frame;

    UIWindow *w = [self mostUsableWindowScene];
    w.frame = frame;
    w.windowLevel = UIWindowLevelAlert + 1000;
    w.backgroundColor = [UIColor colorWithWhite:0.06 alpha:0.94];
    w.layer.cornerRadius = 14;
    w.layer.masksToBounds = YES;
    w.layer.borderWidth = 1;
    w.layer.borderColor = [UIColor colorWithWhite:0.30 alpha:1.0].CGColor;
    w.rootViewController = [UIViewController new];
    w.rootViewController.view.backgroundColor = [UIColor clearColor];
    self.window = w;

    // 标题栏
    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, W, 32)];
    bar.backgroundColor = [UIColor colorWithRed:0.10 green:0.14 blue:0.18 alpha:1.0];
    bar.userInteractionEnabled = YES;
    [w.rootViewController.view addSubview:bar];

    self.titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 6, 140, 20)];
    self.titleLabel.text = @"🔑 解密助手";
    self.titleLabel.textColor = [UIColor colorWithRed:0.4 green:1.0 blue:0.7 alpha:1.0];
    self.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [bar addSubview:self.titleLabel];

    UIButton *minBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    minBtn.frame = CGRectMake(W - 32, 6, 22, 20);
    [minBtn setTitle:@"–" forState:UIControlStateNormal];
    [minBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    minBtn.titleLabel.font = [UIFont boldSystemFontOfSize:20];
    [minBtn addTarget:self action:@selector(toggleCollapsed) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:minBtn];

    // 拖动手势 - 标题栏
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(onPan:)];
    [bar addGestureRecognizer:pan];

    // 统计文本
    self.statsLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 38, W - 20, 36)];
    self.statsLabel.numberOfLines = 0;
    self.statsLabel.textColor = [UIColor colorWithWhite:0.85 alpha:1.0];
    self.statsLabel.font = [UIFont fontWithName:@"Menlo" size:10];
    [w.rootViewController.view addSubview:self.statsLabel];

    // URL 一行: http://ip:port  (点击复制)
    self.urlLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 78, W - 20, 38)];
    self.urlLabel.numberOfLines = 2;
    self.urlLabel.textColor = [UIColor colorWithRed:0.45 green:0.85 blue:1.0 alpha:1.0];
    self.urlLabel.font = [UIFont fontWithName:@"Menlo" size:11];
    self.urlLabel.adjustsFontSizeToFitWidth = YES;
    self.urlLabel.minimumScaleFactor = 0.7;
    self.urlLabel.userInteractionEnabled = YES;
    self.urlLabel.text = @"🌐 (本地服务启动中…)";
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self
                                                                          action:@selector(onCopyURL)];
    [self.urlLabel addGestureRecognizer:tap];
    [w.rootViewController.view addSubview:self.urlLabel];

    // 操作按钮区
    CGFloat by = 122, bw = 66, bh = 26, bx = 10, gap = 8;
    self.openBtn  = [self makeButton:@"日志" color:[UIColor colorWithRed:0.20 green:0.55 blue:0.95 alpha:1.0]
                              frame:CGRectMake(bx, by, bw, bh) action:@selector(onOpenLog)];
    self.pauseBtn = [self makeButton:@"暂停" color:[UIColor colorWithRed:0.65 green:0.55 blue:0.20 alpha:1.0]
                              frame:CGRectMake(bx + (bw+gap), by, bw, bh) action:@selector(onTogglePause)];
    self.clearBtn = [self makeButton:@"清空" color:[UIColor colorWithRed:0.80 green:0.25 blue:0.25 alpha:1.0]
                              frame:CGRectMake(bx + 2*(bw+gap), by, bw, bh) action:@selector(onClear)];

    [w.rootViewController.view addSubview:self.openBtn];
    [w.rootViewController.view addSubview:self.pauseBtn];
    [w.rootViewController.view addSubview:self.clearBtn];

    w.hidden = NO;

    // 定时刷新统计 (1 秒)
    self.statsTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self
                                                     selector:@selector(refreshStats)
                                                     userInfo:nil repeats:YES];
    [self refreshStats];
}

- (UIButton *)makeButton:(NSString *)t color:(UIColor *)c frame:(CGRect)f action:(SEL)sel {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = f;
    [b setTitle:t forState:UIControlStateNormal];
    [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    b.backgroundColor = c;
    b.layer.cornerRadius = 6;
    [b addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (void)refreshStats {
    DHLogStore *s = [DHLogStore shared];
    NSUInteger d = [s countForCategory:DHCategoryDigest];
    NSUInteger h = [s countForCategory:DHCategoryHMAC];
    NSUInteger sym = [s countForCategory:DHCategorySymmetric];
    NSUInteger asym = [s countForCategory:DHCategoryAsymmetric];
    NSString *state = s.paused ? @"⏸ 已暂停" : @"▶ 运行中";
    self.statsLabel.text = [NSString stringWithFormat:
        @"%@  总:%lu  摘要:%lu\nHMAC:%lu 对称:%lu RSA:%lu",
        state, (unsigned long)[s totalCount],
        (unsigned long)d, (unsigned long)h, (unsigned long)sym, (unsigned long)asym];

    uint16_t port = dh_http_port();
    if (port > 0) {
        self.urlLabel.text = [NSString stringWithFormat:@"🌐 %@\n(点这里复制)", dh_http_url()];
    } else {
        self.urlLabel.text = @"🌐 (本地服务启动中…)";
    }
}

- (void)onCopyURL {
    NSString *u = dh_http_url();
    if (!u || ![u hasPrefix:@"http"]) return;
    [UIPasteboard generalPasteboard].string = u;
    // 悬浮窗的 rootVC 在 Alert+1000 层级, present UIAlertController 不可靠.
    // 直接改 label 文字反馈, 1.2s 后 refreshStats 会自动恢复.
    NSString *original = self.urlLabel.text;
    self.urlLabel.text = @"✓ 已复制!";
    self.urlLabel.textColor = [UIColor colorWithRed:0.4 green:1.0 blue:0.6 alpha:1.0];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        self.urlLabel.textColor = [UIColor colorWithRed:0.45 green:0.85 blue:1.0 alpha:1.0];
        if ([self.urlLabel.text isEqualToString:@"✓ 已复制!"]) self.urlLabel.text = original;
    });
}

- (void)onPan:(UIPanGestureRecognizer *)g {
    CGPoint t = [g translationInView:g.view.window];
    if (g.state == UIGestureRecognizerStateChanged) {
        CGRect f = self.window.frame;
        f.origin.x += t.x;
        f.origin.y += t.y;
        // 限制在屏幕内
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
    CGRect target;
    if (self.collapsed) {
        target = CGRectMake(self.window.frame.origin.x, self.window.frame.origin.y, 100, 32);
    } else {
        target = self.expandedFrame;
        target.origin.x = self.window.frame.origin.x;
        target.origin.y = self.window.frame.origin.y;
    }
    [UIView animateWithDuration:0.25 animations:^{
        self.window.frame = target;
        self.statsLabel.alpha = self.collapsed ? 0 : 1;
        self.urlLabel.alpha   = self.collapsed ? 0 : 1;
        self.openBtn.alpha    = self.collapsed ? 0 : 1;
        self.pauseBtn.alpha   = self.collapsed ? 0 : 1;
        self.clearBtn.alpha   = self.collapsed ? 0 : 1;
    }];
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
    // 二次确认: 把按钮变红 + 文字变 "再点一次", 3 秒内再点才真正清空, 否则恢复
    if ([self.clearBtn.titleLabel.text isEqualToString:@"再点一次"]) {
        [[DHLogStore shared] clearAll];
        [self.clearBtn setTitle:@"清空" forState:UIControlStateNormal];
        self.clearBtn.backgroundColor = [UIColor colorWithRed:0.80 green:0.25 blue:0.25 alpha:1.0];
        [self refreshStats];
        return;
    }
    [self.clearBtn setTitle:@"再点一次" forState:UIControlStateNormal];
    self.clearBtn.backgroundColor = [UIColor colorWithRed:1.0 green:0.40 blue:0.40 alpha:1.0];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if ([self.clearBtn.titleLabel.text isEqualToString:@"再点一次"]) {
            [self.clearBtn setTitle:@"清空" forState:UIControlStateNormal];
            self.clearBtn.backgroundColor = [UIColor colorWithRed:0.80 green:0.25 blue:0.25 alpha:1.0];
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

void dh_ui_install_floating(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gFloat) return;
        if (!dh_scene_ready()) {
            // scene 还没准备好, 退后再试; 不要错误地把 gFloat 设上, 否则永远不出现
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ dh_ui_install_floating(); });
            return;
        }
        gFloat = [[DHFloatingController alloc] init];
    });
}
