// macho_dump.m — 见 macho_dump.h
#import "macho_dump.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <mach/machine.h>
#import <libkern/OSByteOrder.h>

@implementation DHDumpImage
@end

static NSError *dh_dump_err(NSString *msg) {
    return [NSError errorWithDomain:@"com.decrypthelper.dump"
                               code:-1
                           userInfo:@{NSLocalizedDescriptionKey: msg ?: @"未知错误"}];
}

// 在内存 header 里找 LC_ENCRYPTION_INFO_64, 返回是否找到, 并输出 off/size/id。
static BOOL find_encryption_info(const struct mach_header *mh,
                                 uint32_t *cryptoff, uint32_t *cryptsize, uint32_t *cryptid) {
    if (mh->magic != MH_MAGIC_64 && mh->magic != MH_CIGAM_64) return NO;
    const uint8_t *cur = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmdsize == 0) break;
        if (lc->cmd == LC_ENCRYPTION_INFO_64) {
            const struct encryption_info_command_64 *ei =
                (const struct encryption_info_command_64 *)lc;
            if (cryptoff)  *cryptoff  = ei->cryptoff;
            if (cryptsize) *cryptsize = ei->cryptsize;
            if (cryptid)   *cryptid   = ei->cryptid;
            return YES;
        }
        cur += lc->cmdsize;
    }
    return NO;
}

NSArray<DHDumpImage *> *dh_dump_list_images(void) {
    NSMutableArray<DHDumpImage *> *out = [NSMutableArray array];
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSString *execPath   = [[NSBundle mainBundle] executablePath];
    if (bundlePath.length == 0) return out;

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *cname = _dyld_get_image_name(i);
        if (!cname) continue;
        NSString *path = [NSString stringWithUTF8String:cname];
        if (!path || ![path hasPrefix:bundlePath]) continue;   // 只看本 App bundle 内的镜像

        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh) continue;
        if (mh->magic != MH_MAGIC_64 && mh->magic != MH_CIGAM_64) continue;   // 仅 64 位

        uint32_t cid = 0, csize = 0, coff = 0;
        find_encryption_info(mh, &coff, &csize, &cid);

        DHDumpImage *img = [DHDumpImage new];
        img.path      = path;
        img.name      = [path lastPathComponent];
        img.kind      = (execPath && [path isEqualToString:execPath]) ? @"main" : @"framework";
        img.cryptid   = cid;
        img.cryptsize = csize;
        img.header    = mh;
        [out addObject:img];
    }
    return out;
}

// 在磁盘文件里定位当前 cpu 对应的 thin slice (处理 FAT)。成功 YES 并输出 off/size。
static BOOL locate_slice(NSData *fileData, const struct mach_header *mh,
                         uint64_t *sliceOff, uint64_t *sliceSize, NSString **err) {
    *sliceOff = 0;
    *sliceSize = fileData.length;
    if (fileData.length < sizeof(uint32_t)) { if (err) *err = @"文件过小"; return NO; }

    const uint8_t *fb = (const uint8_t *)fileData.bytes;
    uint32_t magic = *(const uint32_t *)fb;

    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        return YES;   // 已是 thin 64 位
    }
    if (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        if (err) *err = @"暂不支持 fat_arch_64 容器";
        return NO;
    }
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        if (fileData.length < sizeof(struct fat_header)) { if (err) *err = @"FAT 头损坏"; return NO; }
        const struct fat_header *fh = (const struct fat_header *)fb;
        uint32_t narch = OSSwapBigToHostInt32(fh->nfat_arch);
        cpu_type_t    wantCpu = mh->cputype;
        cpu_subtype_t wantSub = mh->cpusubtype & ~CPU_SUBTYPE_MASK;

        if (fileData.length < sizeof(struct fat_header) + (uint64_t)narch * sizeof(struct fat_arch)) {
            if (err) *err = @"FAT arch 表越界"; return NO;
        }
        const struct fat_arch *fa = (const struct fat_arch *)(fb + sizeof(struct fat_header));

        // 优先精确匹配 cputype + cpusubtype, 否则退化为仅 cputype 匹配
        long fallback = -1;
        for (uint32_t a = 0; a < narch; a++) {
            cpu_type_t    cpu = (cpu_type_t)OSSwapBigToHostInt32((uint32_t)fa[a].cputype);
            cpu_subtype_t sub = (cpu_subtype_t)(OSSwapBigToHostInt32((uint32_t)fa[a].cpusubtype) & ~CPU_SUBTYPE_MASK);
            if (cpu != wantCpu) continue;
            if (fallback < 0) fallback = a;
            if (sub == wantSub) {
                *sliceOff  = OSSwapBigToHostInt32(fa[a].offset);
                *sliceSize = OSSwapBigToHostInt32(fa[a].size);
                return YES;
            }
        }
        if (fallback >= 0) {
            *sliceOff  = OSSwapBigToHostInt32(fa[fallback].offset);
            *sliceSize = OSSwapBigToHostInt32(fa[fallback].size);
            return YES;
        }
        if (err) *err = @"FAT 中未找到当前架构 slice";
        return NO;
    }
    if (err) *err = @"未知的 Mach-O magic";
    return NO;
}

NSData *dh_dump_decrypt_image(DHDumpImage *img, NSError **error) {
    const struct mach_header *mh = img.header;
    if (!mh) { if (error) *error = dh_dump_err(@"镜像 header 为空"); return nil; }

    // 1. 内存里读取加密信息
    uint32_t cryptoff = 0, cryptsize = 0, cryptid = 0;
    BOOL hasEnc = find_encryption_info(mh, &cryptoff, &cryptsize, &cryptid);

    // 2. 读磁盘原文件
    NSError *rerr = nil;
    NSData *fileData = [NSData dataWithContentsOfFile:img.path options:0 error:&rerr];
    if (!fileData) {
        if (error) *error = dh_dump_err([NSString stringWithFormat:@"读取文件失败: %@", rerr.localizedDescription]);
        return nil;
    }

    // 3. 定位 thin slice
    uint64_t sliceOff = 0, sliceSize = 0;
    NSString *serr = nil;
    if (!locate_slice(fileData, mh, &sliceOff, &sliceSize, &serr)) {
        if (error) *error = dh_dump_err(serr ?: @"定位 slice 失败");
        return nil;
    }
    if (sliceOff + sliceSize > fileData.length) {
        if (error) *error = dh_dump_err(@"slice 范围越界");
        return nil;
    }

    // 4. 复制 thin slice 为可写副本
    NSMutableData *out = [NSMutableData dataWithBytes:((const uint8_t *)fileData.bytes + sliceOff)
                                              length:(NSUInteger)sliceSize];
    uint8_t *ob = (uint8_t *)out.mutableBytes;

    // 5. 用内存中已解密的数据覆盖加密段
    if (hasEnc && cryptid != 0 && cryptsize > 0) {
        if ((uint64_t)cryptoff + cryptsize > out.length) {
            if (error) *error = dh_dump_err(@"加密段范围超出 slice");
            return nil;
        }
        // cryptoff 是相对 thin Mach-O 文件起点的偏移; 内存中该 thin 镜像基址即 mh,
        // 故已解密数据位于 (uint8_t*)mh + cryptoff。
        const uint8_t *decrypted = (const uint8_t *)mh + cryptoff;
        memcpy(ob + cryptoff, decrypted, cryptsize);
    }

    // 6. 把副本里的 cryptid 改成 0
    if (hasEnc) {
        struct mach_header_64 *oh = (struct mach_header_64 *)ob;
        uint8_t *cur = ob + sizeof(struct mach_header_64);
        uint8_t *end = ob + out.length;
        for (uint32_t i = 0; i < oh->ncmds; i++) {
            if (cur + sizeof(struct load_command) > end) break;
            struct load_command *lc = (struct load_command *)cur;
            if (lc->cmdsize == 0) break;
            if (lc->cmd == LC_ENCRYPTION_INFO_64) {
                if (cur + sizeof(struct encryption_info_command_64) > end) break;
                struct encryption_info_command_64 *ei = (struct encryption_info_command_64 *)cur;
                ei->cryptid = 0;
                break;
            }
            cur += lc->cmdsize;
        }
    }

    return out;
}
