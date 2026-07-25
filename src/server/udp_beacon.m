// udp_beacon.m - UDP 广播信标，替代 Bonjour。
// 注入场景下宿主 App 没有 NSBonjourServices / NSLocalNetworkUsageDescription /
// com.apple.developer.networking.localnetwork entitlement，NSNetService publish 必然失败。
// 改用纯 BSD socket UDP broadcast，无需任何 plist 声明或用户授权。

#import <Foundation/Foundation.h>
#import "udp_beacon.h"
#import "dh_health.h"

#ifndef DH_VERSION_STR
#define DH_VERSION_STR "0.0.0"
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static dispatch_source_t gBeaconTimer = nil;
static int gBeaconFD = -1;
static uint16_t gBeaconHTTPPort = 0;

static NSString *dh_beacon_instance_id(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        cached = NSUUID.UUID.UUIDString.lowercaseString;
    });
    return cached;
}

static NSData *dh_beacon_payload(void) {
    NSBundle *bundle = NSBundle.mainBundle;
    NSDictionary *info = bundle.infoDictionary ?: @{};
    NSString *appName = info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"]
                        ?: NSProcessInfo.processInfo.processName ?: @"iOS App";
    NSString *bundleID = bundle.bundleIdentifier ?: @"";
    NSString *appVersion = info[@"CFBundleShortVersionString"] ?: info[@"CFBundleVersion"] ?: @"";

    NSDictionary *payload = @{
        @"type":        @"idh-beacon",
        @"protocol":    @"2",
        @"id":          dh_beacon_instance_id(),
        @"app_name":    appName,
        @"bundle":      bundleID,
        @"app_version": appVersion,
        @"idh_version": @DH_VERSION_STR,
        @"port":        @(gBeaconHTTPPort),
        @"mcp_path":    @"/api/mcp",
        @"panel_path":  @"/",
        @"pid":         @(NSProcessInfo.processInfo.processIdentifier),
    };
    return [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
}

static void dh_beacon_send(void) {
    if (gBeaconFD < 0) return;

    NSData *payload = dh_beacon_payload();
    if (!payload) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DH_BEACON_PORT);
    dest.sin_addr.s_addr = INADDR_BROADCAST;

    sendto(gBeaconFD, payload.bytes, payload.length, 0,
           (struct sockaddr *)&dest, sizeof(dest));
}

void dh_beacon_start(uint16_t port) {
    if (port == 0) return;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gBeaconHTTPPort = port;

        // 创建 UDP socket
        gBeaconFD = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (gBeaconFD < 0) {
            NSLog(@"[IOSDecryptHub] UDP 信标: socket 创建失败");
            dh_diag_append(DH_DIAG_GENERAL, "ERROR", "UDP beacon: socket() failed");
            return;
        }

        // 允许广播
        int broadcast = 1;
        setsockopt(gBeaconFD, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

        // 定时器每 2 秒广播一次
        gBeaconTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                              dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
        dispatch_source_set_timer(gBeaconTimer,
                                  dispatch_time(DISPATCH_TIME_NOW, 0),
                                  2 * NSEC_PER_SEC,
                                  500 * NSEC_PER_MSEC);  // 0.5s 容差
        dispatch_source_set_event_handler(gBeaconTimer, ^{
            dh_beacon_send();
        });
        dispatch_resume(gBeaconTimer);

        // 立即发一次
        dh_beacon_send();

        NSLog(@"[IOSDecryptHub] UDP 信标已启动: 广播端口 %d, HTTP 端口 %u", DH_BEACON_PORT, port);
        dh_diag_append(DH_DIAG_GENERAL, "INFO", "UDP beacon started");
    });
}

void dh_beacon_stop(void) {
    if (gBeaconTimer) {
        dispatch_source_cancel(gBeaconTimer);
        gBeaconTimer = nil;
    }
    if (gBeaconFD >= 0) {
        close(gBeaconFD);
        gBeaconFD = -1;
    }
}
