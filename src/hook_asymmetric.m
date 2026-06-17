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
        }
        if (err) CFRelease(err);
        CFRelease(pub);
    }
    return out;
}

// ---------- SecKeyCreateSignature ----------
static CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static CFDataRef hooked_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm,
                                              CFDataRef dataToSign, CFErrorRef *error) {
    CFDataRef out = orig_SecKeyCreateSignature(key, algorithm, dataToSign, error);
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
}
