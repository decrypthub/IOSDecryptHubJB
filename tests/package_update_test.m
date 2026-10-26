#import <Foundation/Foundation.h>
#import "dh_package_update.h"

int main(void) {
    @autoreleasepool {
        NSString *index = @"Package: com.other\nVersion: 99.0.0\nArchitecture: iphoneos-arm64\n\n"
            "Package: com.iosdecrypthub\nVersion: 1.27.9\nArchitecture: iphoneos-arm64\n\n"
            "Package: com.iosdecrypthub\nVersion: 1.27.10\nArchitecture: iphoneos-arm64\n\n"
            "Package: com.iosdecrypthub\nVersion: 1.27.8\nArchitecture: iphoneos-arm64e";
        NSData *data = [index dataUsingEncoding:NSUTF8StringEncoding];
        NSCAssert([DHParsePackageIndex(data, @"iphoneos-arm64")[@"version"] isEqualToString:@"1.27.10"], @"numeric newest version");
        NSCAssert([DHParsePackageIndex(data, @"iphoneos-arm64e")[@"version"] isEqualToString:@"1.27.8"], @"package architecture isolation");
        NSCAssert(DHParsePackageIndex(data, @"unknown") == nil, @"no architecture fallback");
        NSData *crlf = [[index stringByReplacingOccurrencesOfString:@"\n" withString:@"\r\n"] dataUsingEncoding:NSUTF8StringEncoding];
        NSCAssert([DHParsePackageIndex(crlf, @"iphoneos-arm64e")[@"version"] isEqualToString:@"1.27.8"], @"CRLF and final stanza");
        NSCAssert(DHParsePackageIndex([NSData data], @"iphoneos-arm64") == nil, @"empty index fails");
        NSString *bad = @"Package: com.iosdecrypthub\nVersion: 99.evil.0\nArchitecture: iphoneos-arm64";
        NSCAssert(DHParsePackageIndex([bad dataUsingEncoding:NSUTF8StringEncoding], @"iphoneos-arm64") == nil, @"malformed version fails");
        NSCAssert(DHPackageManagerRequired(@"install") && DHPackageManagerRequired(@"rollback"), @"old engine writes must be denied");
        NSCAssert(!DHPackageManagerRequired(@"check") && !DHPackageManagerRequired(@"set-enabled"), @"scope and checks remain available");
        puts("PASS: package update versions, architectures, malformed index, and legacy write policy");
    }
    return 0;
}
