// bonjour_publisher.m - 用 NSNetService 发布既有 BSD socket，不重复占用 HTTP 端口。

#import <Foundation/Foundation.h>
#import "bonjour_publisher.h"
#import "dh_health.h"

#ifndef DH_VERSION_STR
#define DH_VERSION_STR "0.0.0"
#endif

static NSString *const DHBonjourType = @"_idh-mcp._tcp.";

static NSNetService *gBonjourService = nil;
static NSObject<NSNetServiceDelegate> *gBonjourDelegate = nil;
static NSThread *gBonjourThread = nil;

static NSData *dh_txt_value(NSString *value) {
    NSData *data = [(value ?: @"") dataUsingEncoding:NSUTF8StringEncoding];
    if (data.length <= 255) return data;
    // DNS-SD 单个 TXT value 上限 255 字节；按组合字符裁剪，避免截断 UTF-8。
    __block NSRange kept = NSMakeRange(0, 0);
    [value enumerateSubstringsInRange:NSMakeRange(0, value.length)
                              options:NSStringEnumerationByComposedCharacterSequences
                           usingBlock:^(NSString *part, NSRange range, NSRange enclosing, BOOL *stop) {
        (void)part; (void)enclosing;
        NSRange candidate = NSMakeRange(0, NSMaxRange(range));
        NSData *candidateData = [[value substringWithRange:candidate]
                                  dataUsingEncoding:NSUTF8StringEncoding];
        if (candidateData.length > 255) { *stop = YES; return; }
        kept = candidate;
    }];
    return [[value substringWithRange:kept] dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
}

static NSDictionary<NSString *, NSData *> *dh_bonjour_txt_record(NSString *instanceID) {
    NSBundle *bundle = NSBundle.mainBundle;
    NSDictionary *info = bundle.infoDictionary ?: @{};
    NSString *appName = info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"]
                        ?: NSProcessInfo.processInfo.processName ?: @"iOS App";
    NSString *bundleID = bundle.bundleIdentifier ?: @"";
    NSString *appVersion = info[@"CFBundleShortVersionString"] ?: info[@"CFBundleVersion"] ?: @"";
    return @{
        @"protocol":    dh_txt_value(@"1"),
        @"id":          dh_txt_value(instanceID),
        @"app_name":    dh_txt_value(appName),
        @"bundle":      dh_txt_value(bundleID),
        @"app_version": dh_txt_value(appVersion),
        @"idh_version": dh_txt_value(@DH_VERSION_STR),
        @"mcp_path":    dh_txt_value(@"/api/mcp"),
        @"panel_path":  dh_txt_value(@"/"),
        @"pid":         dh_txt_value([NSString stringWithFormat:@"%d", NSProcessInfo.processInfo.processIdentifier]),
    };
}

@interface DHBonjourDelegate : NSObject <NSNetServiceDelegate>
@end

@implementation DHBonjourDelegate

- (void)netServiceDidPublish:(NSNetService *)sender {
    NSString *message = [NSString stringWithFormat:@"Bonjour 服务已发布: %@.%@ port=%ld",
                         sender.name, sender.type, (long)sender.port];
    NSLog(@"[IOSDecryptHub] %@", message);
    dh_diag_append(DH_DIAG_GENERAL, "INFO", message.UTF8String);
}

- (void)netService:(NSNetService *)sender
      didNotPublish:(NSDictionary<NSString *, NSNumber *> *)errorDict {
    NSString *message = [NSString stringWithFormat:@"Bonjour 发布失败: %@ error=%@",
                         sender.name, errorDict];
    NSLog(@"[IOSDecryptHub] %@", message);
    dh_diag_append(DH_DIAG_GENERAL, "ERROR", message.UTF8String);
}

@end

void dh_bonjour_start(uint16_t port) {
    if (port == 0) return;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gBonjourThread = [[NSThread alloc] initWithBlock:^{
            @autoreleasepool {
                NSString *instanceID = NSUUID.UUID.UUIDString.lowercaseString;
                NSString *serviceName = [NSString stringWithFormat:@"idh-%@",
                                         [instanceID substringToIndex:8]];
                DHBonjourDelegate *delegate = [DHBonjourDelegate new];
                NSNetService *service = [[NSNetService alloc] initWithDomain:@"local."
                                                                        type:DHBonjourType
                                                                        name:serviceName
                                                                        port:(int)port];
                service.delegate = delegate;
                service.TXTRecordData = [NSNetService dataFromTXTRecordDictionary:
                                         dh_bonjour_txt_record(instanceID)];
                gBonjourDelegate = delegate;
                gBonjourService = service;
                [service publish];

                while (!NSThread.currentThread.cancelled) {
                    @autoreleasepool {
                        [NSRunLoop.currentRunLoop runMode:NSDefaultRunLoopMode
                                               beforeDate:[NSDate dateWithTimeIntervalSinceNow:60.0]];
                    }
                }
                [service stop];
            }
        }];
        gBonjourThread.name = @"com.decrypthelper.bonjour";
        [gBonjourThread start];
    });
}

