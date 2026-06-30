// hook_asymmetric.m
// Hook Security.framework 的非对称算法:
//   SecKeyCreateSignature / SecKeyVerifySignature
//   SecKeyCreateEncryptedData / SecKeyCreateDecryptedData
//
// 注: SecKeyAlgorithm 是 CFStringRef 常量, 直接当字符串描述即可.

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_CRYPTO
#import "dh_health.h"
#import "dh_capture.h"

static NSString *describe_key(SecKeyRef key) {
    if (!key) return @"(null)";
    NSMutableString *out = [NSMutableString string];
    size_t bytes = SecKeyGetBlockSize(key);
    [out appendFormat:@"blockSize=%lu (≈%lu bits)", (unsigned long)bytes, (unsigned long)(bytes * 8)];
    CFDictionaryRef attrs = SecKeyCopyAttributes(key);
    if (attrs) {
        NSDictionary *d = (__bridge_transfer NSDictionary *)attrs;
        NSString *type = d[(__bridge NSString *)kSecAttrKeyType];
        NSString *cls  = d[(__bridge NSString *)kSecAttrKeyClass];
        NSNumber *sz   = d[(__bridge NSString *)kSecAttrKeySizeInBits];
        if (type) [out appendFormat:@" type=%@", type];
        if (cls)  [out appendFormat:@" class=%@", cls];
        if (sz)   [out appendFormat:@" sizeInBits=%@", sz];
    }
    // 尝试导出公钥的外部表示用于指纹
    SecKeyRef pub = SecKeyCopyPublicKey(key);
    if (pub) {
        CFErrorRef err = NULL;
        CFDataRef pubData = SecKeyCopyExternalRepresentation(pub, &err);
        if (pubData) {
            NSData *pd = (__bridge_transfer NSData *)pubData;
            // 取前 24 字节做指纹
            NSUInteger n = MIN(pd.length, 24u);
            [out appendFormat:@" pubFP=%@…", DHHexFromData([pd subdataWithRange:NSMakeRange(0,n)])];
        } else {
            // fail-loud: 导出失败时明确标注, 而非留空让人以为没有公钥
            [out appendFormat:@" pubExportFailed(err=%ld)", err ? (long)CFErrorGetCode(err) : -1L];
        }
        if (err) CFRelease(err);
        CFRelease(pub);
    } else {
        [out appendString:@" pubKeyUnavailable"];
    }
    return out;
}

// ---------- SecKeyCreateSignature ----------
static CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static CFDataRef hooked_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm,
                                              CFDataRef dataToSign, CFErrorRef *error) {
    CFDataRef out = orig_SecKeyCreateSignature(key, algorithm, dataToSign, error);
    if (!dh_capture_sub_enabled(DH_CAP_ASYMMETRIC)) return out;
    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategoryAsymmetric;
    e.algorithm  = [NSString stringWithFormat:@"SIGN-%@", (__bridge NSString *)algorithm];
    e.operation  = @"sign";
    e.publicKeyInfo = describe_key(key);
    e.input      = dataToSign ? (__bridge NSData *)dataToSign : nil;
    e.output     = out ? [(__bridge NSData *)out copy] : nil;
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
    return out;
}

// ---------- SecKeyVerifySignature ----------
static Boolean (*orig_SecKeyVerifySignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFDataRef, CFErrorRef *);
static Boolean hooked_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm,
                                            CFDataRef signedData, CFDataRef signature,
                                            CFErrorRef *error) {
    Boolean ok = orig_SecKeyVerifySignature(key, algorithm, signedData, signature, error);
    if (!dh_capture_sub_enabled(DH_CAP_ASYMMETRIC)) return ok;
    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategoryAsymmetric;
    e.algorithm  = [NSString stringWithFormat:@"VERIFY-%@", (__bridge NSString *)algorithm];
    e.operation  = ok ? @"verify (ok)" : @"verify (fail)";
    e.publicKeyInfo = describe_key(key);
    e.input      = signedData ? (__bridge NSData *)signedData : nil;
    e.output     = signature ? [(__bridge NSData *)signature copy] : nil;
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
    return ok;
}

// ---------- SecKeyCreateEncryptedData ----------
static CFDataRef (*orig_SecKeyCreateEncryptedData)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static CFDataRef hooked_SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm,
                                                  CFDataRef plaintext, CFErrorRef *error) {
    CFDataRef out = orig_SecKeyCreateEncryptedData(key, algorithm, plaintext, error);
    if (!dh_capture_sub_enabled(DH_CAP_ASYMMETRIC)) return out;
    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategoryAsymmetric;
    e.algorithm  = [NSString stringWithFormat:@"ENC-%@", (__bridge NSString *)algorithm];
    e.operation  = @"encrypt";
    e.publicKeyInfo = describe_key(key);
    e.input      = plaintext ? (__bridge NSData *)plaintext : nil;
    e.output     = out ? [(__bridge NSData *)out copy] : nil;
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
    return out;
}

// ---------- SecKeyCreateDecryptedData ----------
static CFDataRef (*orig_SecKeyCreateDecryptedData)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static CFDataRef hooked_SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm algorithm,
                                                  CFDataRef ciphertext, CFErrorRef *error) {
    CFDataRef out = orig_SecKeyCreateDecryptedData(key, algorithm, ciphertext, error);
    if (!dh_capture_sub_enabled(DH_CAP_ASYMMETRIC)) return out;
    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategoryAsymmetric;
    e.algorithm  = [NSString stringWithFormat:@"DEC-%@", (__bridge NSString *)algorithm];
    e.operation  = @"decrypt";
    e.publicKeyInfo = describe_key(key);
    e.input      = ciphertext ? (__bridge NSData *)ciphertext : nil;
    e.output     = out ? [(__bridge NSData *)out copy] : nil;
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
    return out;
}

void dh_install_asymmetric_hooks(void) {
    struct rebinding r[] = {
        {"SecKeyCreateSignature",     hooked_SecKeyCreateSignature,     (void **)&orig_SecKeyCreateSignature},
        {"SecKeyVerifySignature",     hooked_SecKeyVerifySignature,     (void **)&orig_SecKeyVerifySignature},
        {"SecKeyCreateEncryptedData", hooked_SecKeyCreateEncryptedData, (void **)&orig_SecKeyCreateEncryptedData},
        {"SecKeyCreateDecryptedData", hooked_SecKeyCreateDecryptedData, (void **)&orig_SecKeyCreateDecryptedData},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    // 注: 不在此做安装后自检 —— Security.framework 可能在 dylib 注入后才被宿主加载,
    // 此刻 orig 仍为 NULL 是正常的(随后 add-image 回调会补挂), 误报反而违背 fail-loud 初衷.
    // 真正没挂上的情形会在 SecKey* 调用发生却无日志时体现.
}
