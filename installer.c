/* OC2MAC1: OC2UPD1 record order, POSIX mode & 0777, FILETIME 100ns times.
 * Never consume Windows attributes or managed Process.StartTime on macOS.
 *
 * No arguments: read adjacent install.plan, detach, handshake, await NOTE_EXIT.
 * --metadata PATH: decimal mode, one space, mtime FILETIME, newline.
 * --owner PID: exact proc_pidinfo creation FILETIME, newline.
 * Query modes do not detach, read a plan, write markers or modify files.
 *
 * Wire: magic[8], u32 pid, i64 creation, u32 cleanup, five UTF-16LE
 * strings (cache boundary, plugin boundary, plugins, cache, current DLL),
 * u32 group count. Each group has checks, moves, installs, directories, prune.
 * Entry: u32 kind, path/saved/hash strings, u32 mode, i64 mtime, i64 size,
 * u32 children. Lists/strings start with u32 counts; integers are LE.
 * Check kinds: 0 absent, 1 file, 2 directory inventory, 3 directory exists.
 * Move kind 1 permits a missing/changed cleanup file to be retained/reported;
 * other move/install records describe files regardless of their check kind.
 *
 * Directory fds prevent symlink traversal, not malicious same-user rename
 * of a directory already opened by this process. Source rename has no atomic
 * inode predicate on Darwin; detect conflicts before/after and retain evidence.
 * Cross-volume backup (EXDEV), unsupported permissions/time precision, and
 * unavailable process observation fail closed. No recursive deletion. */
#define _DARWIN_C_SOURCE 1
#include <CommonCrypto/CommonDigest.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_ITEMS 200000u
#define MAX_TEXT 32760u
#define MAX_PLAN_BYTES (512u * 1024u * 1024u)
#define WINDOWS_EPOCH INT64_C(11644473600)
#define TICKS INT64_C(10000000)

typedef struct {
    uint32_t kind, attributes, children;
    char *path, *saved, *hash;
    int64_t time, size;
} Entry;
typedef struct {
    uint32_t nc, nm, ni, nd, np;
    Entry *checks, *moves, *installs;
    char **directories, **prune;
} Group;
typedef struct {
    uint32_t pid, cleanup, count;
    int64_t creation;
    char *cache_boundary, *plugin_boundary, *plugins, *cache, *current;
    Group *groups;
} Plan;
typedef struct {
    const char *path;
    int fd;
    struct stat identity;
} Boundary;
typedef struct {
    int fd;
    char name[NAME_MAX + 1];
} Parent;
typedef struct {
    int present;
    struct stat identity;
} Owned;

static Plan plan;
static Boundary cb = { .fd = -1 }, pb = { .fd = -1 };
static char home[PATH_MAX];
static FILE *journal;
static const char *stage = "startup";
static uint32_t budget = MAX_ITEMS;
static int log_failed;
extern char **environ;

static void log_line(const char *level, const char *format, ...)
{
    time_t now = time(NULL);
    struct tm utc;
    va_list args;
    int error = errno;
    if (!journal) return;
    if (!gmtime_r(&now, &utc)) memset(&utc, 0, sizeof(utc));
    if (fprintf(journal, "%04d-%02d-%02dT%02d:%02d:%02dZ [%s] stage=%s ",
                utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                utc.tm_hour, utc.tm_min, utc.tm_sec, level, stage) < 0) log_failed = 1;
    va_start(args, format);
    if (vfprintf(journal, format, args) < 0) log_failed = 1;
    va_end(args);
    if (fputc('\n', journal) == EOF || fflush(journal) != 0 || fsync(fileno(journal)) != 0)
        log_failed = 1;
    errno = error;
}

static int fail(const char *operation, const char *path)
{
    int error = errno ? errno : EINVAL;
    log_line("Warning", "operation=%s path=\"%s\" errno=%d reason=%s",
             operation, path ? path : "", error, strerror(error));
    errno = error;
    return 0;
}

static int reject(const char *operation, const char *path, int error)
{
    errno = error;
    return fail(operation, path);
}

static int join(char out[PATH_MAX], const char *left, const char *right)
{
    int n = snprintf(out, PATH_MAX, "%s/%s", left, right);
    return n >= 0 && n < PATH_MAX ? 1 : reject("path-length", left, ENAMETOOLONG);
}

static int within(const char *path, const char *root)
{
    size_t n = strlen(root);
    return !strncmp(path, root, n) && (path[n] == '\0' || path[n] == '/');
}

static int clean(const char *path)
{
    const char *p;
    if (!path || path[0] != '/' || !path[1] || strlen(path) >= PATH_MAX) return 0;
    for (p = path + 1; *p;) {
        const char *start = p;
        size_t n;
        while (*p && *p != '/') {
            if ((unsigned char)*p < 32 || *p == 127) return 0;
            ++p;
        }
        n = (size_t)(p - start);
        if (!n || n > NAME_MAX || (n == 1 && start[0] == '.')
            || (n == 2 && start[0] == '.' && start[1] == '.')) return 0;
        if (*p && !*++p) return 0;
    }
    return 1;
}

static int same_inode(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int same_state(const struct stat *a, const struct stat *b)
{
    return same_inode(a, b) && a->st_mode == b->st_mode && a->st_size == b->st_size
        && a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec
        && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec
        && a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec
        && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}

static int filetime(time_t seconds, long nanoseconds, int64_t *ticks)
{
    int64_t sec = (int64_t)seconds;
    if (nanoseconds < 0 || nanoseconds >= 1000000000L || sec < -WINDOWS_EPOCH
        || sec > INT64_MAX / TICKS - WINDOWS_EPOCH - 1) { errno = EOVERFLOW; return 0; }
    *ticks = (sec + WINDOWS_EPOCH) * TICKS + nanoseconds / 100;
    return 1;
}

/* The boundary itself is no-follow; Steam mappings ABOVE it may resolve. */
static int boundary_open(const char *path)
{
    char parent[PATH_MAX];
    char *slash;
    int fd, result, error;
    if (!clean(path)) { errno = EINVAL; return -1; }
    strcpy(parent, path);
    slash = strrchr(parent, '/');
    *slash = '\0';
    fd = open(parent[0] ? parent : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    result = openat(fd, slash + 1, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    error = errno;
    close(fd);
    errno = error;
    return result;
}

static int boundary_init(Boundary *b, const char *path)
{
    b->path = path;
    b->fd = boundary_open(path);
    if (b->fd < 0 || fstat(b->fd, &b->identity) != 0) return fail("open-boundary", path);
    return 1;
}

static int boundary_current(const Boundary *b)
{
    struct stat st;
    int fd = boundary_open(b->path);
    int ok = fd >= 0 && fstat(fd, &st) == 0 && same_inode(&st, &b->identity);
    if (fd >= 0) close(fd);
    return ok ? 1 : reject("boundary-changed", b->path, ESTALE);
}

static Boundary *scope(const char *path, int mutation)
{
    if (!clean(path)) { reject("invalid-path", path, EINVAL); return NULL; }
    if (within(path, plan.cache) && (!mutation || strcmp(path, plan.cache))) return &cb;
    if (within(path, plan.plugins) && (!mutation || strcmp(path, plan.plugins))) return &pb;
    reject("path-outside-scope", path, EPERM);
    return NULL;
}

static int walk(Boundary *b, const char *path, int create, Parent *out)
{
    char relative[PATH_MAX], *component, *slash;
    int fd;
    out->fd = -1;
    if (!clean(path) || !within(path, b->path) || !strcmp(path, b->path))
        return reject("boundary-relative-path", path, EPERM);
    if (!boundary_current(b)) return 0;
    strcpy(relative, path + strlen(b->path) + 1);
    fd = dup(b->fd);
    if (fd < 0) return fail("dup-boundary", path);
    component = relative;
    while ((slash = strchr(component, '/')) != NULL) {
        int child, error;
        *slash = '\0';
        child = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0 && errno == ENOENT && create) {
            log_line("Debug", "intent=mkdir path=\"%s\" component=\"%s\"", path, component);
            if (log_failed) { close(fd); return reject("journal-failed", path, EIO); }
            if (mkdirat(fd, component, 0755) != 0 && errno != EEXIST) {
                error = errno; close(fd); errno = error; return fail("mkdirat", path);
            }
            child = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (child < 0) {
            error = errno; close(fd); errno = error; return fail("openat-ancestor", path);
        }
        close(fd);
        fd = child;
        component = slash + 1;
    }
    strcpy(out->name, component);
    out->fd = fd;
    return 1;
}

static int parent_for(const char *path, int mutation, Parent *out)
{
    Boundary *b = scope(path, mutation);
    return b && walk(b, path, 0, out);
}

static int parent_current(const char *path, const Parent *p)
{
    Parent fresh;
    struct stat a, b;
    int ok;
    if (!parent_for(path, 0, &fresh)) return 0;
    ok = fstat(p->fd, &a) == 0 && fstat(fresh.fd, &b) == 0 && same_inode(&a, &b);
    close(fresh.fd);
    return ok ? 1 : reject("parent-replaced", path, ESTALE);
}

static int scoped_open(const char *path, int flags)
{
    Boundary *b = scope(path, 0);
    Parent p;
    int fd, error;
    if (!b) return -1;
    if (!strcmp(path, b->path)) {
        if (!boundary_current(b)) return -1;
        return openat(b->fd, ".", flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    }
    if (!walk(b, path, 0, &p)) return -1;
    fd = openat(p.fd, p.name, flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    error = errno;
    close(p.fd);
    errno = error;
    return fd;
}

static int path_stat(const char *path, struct stat *st)
{
    int fd = scoped_open(path, O_RDONLY);
    int ok, error;
    if (fd < 0) return 0;
    ok = fstat(fd, st) == 0;
    error = errno;
    close(fd);
    errno = error;
    return ok;
}

static int validate_path(const char *path, int mutation)
{
    Boundary *b = scope(path, mutation);
    Parent p;
    struct stat st;
    int result, error;
    if (!b) return 0;
    if (!strcmp(path, b->path)) return boundary_current(b);
    if (!walk(b, path, 0, &p)) return errno == ENOENT;
    result = fstatat(p.fd, p.name, &st, AT_SYMLINK_NOFOLLOW);
    error = errno;
    close(p.fd);
    if (result < 0) return error == ENOENT ? 1 : reject("stat-path", path, error);
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) return reject("reject-link-or-special", path, EINVAL);
    return 1;
}

static int missing(const char *path)
{
    Parent p;
    struct stat st;
    int result, error;
    if (!scope(path, 1)) return 0;
    if (!parent_for(path, 1, &p)) return errno == ENOENT;
    result = fstatat(p.fd, p.name, &st, AT_SYMLINK_NOFOLLOW);
    error = errno;
    close(p.fd);
    return result < 0 && error == ENOENT ? 1 : reject("expected-absent", path, result == 0 ? EEXIST : error);
}

static int make_directory(const char *path)
{
    Parent p;
    int fd, ok = 0, error;
    if (!clean(path) || !within(path, plan.plugins)) return reject("mkdir-scope", path, EPERM);
    fd = scoped_open(plan.plugins, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return fail("plugins-root-missing", plan.plugins);
    close(fd);
    if (!strcmp(path, plan.plugins)) return 1;
    if (!walk(&pb, path, 1, &p)) return 0;
    log_line("Debug", "intent=mkdir path=\"%s\"", path);
    if (log_failed) { close(p.fd); return reject("journal-failed", path, EIO); }
    if (parent_current(path, &p)
        && (mkdirat(p.fd, p.name, 0755) == 0 || errno == EEXIST)) {
        fd = openat(p.fd, p.name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0) { close(fd); ok = 1; }
    }
    error = errno;
    close(p.fd);
    errno = error;
    return ok ? 1 : fail("make-directory", path);
}

/* CommonCrypto exists on both deployment targets. Suppress only SDK deprecation. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static int hash_fd(int fd, char hex[65], struct stat *observed)
{
    struct stat before, after;
    unsigned char buffer[65536], digest[CC_SHA256_DIGEST_LENGTH];
    static const char digits[] = "0123456789abcdef";
    CC_SHA256_CTX context;
    ssize_t n;
    size_t i;
    if (fstat(fd, &before) != 0) return 0;
    if (!S_ISREG(before.st_mode)) { errno = EINVAL; return 0; }
    if (lseek(fd, 0, SEEK_SET) < 0) return 0;
    if (CC_SHA256_Init(&context) != 1) { errno = EIO; return 0; }
    for (;;) {
        n = read(fd, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return 0;
        if (!n) break;
        if (CC_SHA256_Update(&context, buffer, (CC_LONG)n) != 1) { errno = EIO; return 0; }
    }
    if (CC_SHA256_Final(digest, &context) != 1) { errno = EIO; return 0; }
    if (fstat(fd, &after) != 0) return 0;
    if (!same_state(&before, &after)) { errno = ESTALE; return 0; }
    for (i = 0; i < sizeof(digest); ++i) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    hex[64] = '\0';
    if (observed) *observed = after;
    return 1;
}
#pragma clang diagnostic pop

static int metadata_matches(const struct stat *st, const Entry *e)
{
    int64_t ticks;
    return S_ISREG(st->st_mode) && st->st_size == e->size
        && (uint32_t)(st->st_mode & 0777) == e->attributes
        && filetime(st->st_mtimespec.tv_sec, st->st_mtimespec.tv_nsec, &ticks) && ticks == e->time;
}

static int verify_fd(int fd, const Entry *e, int metadata,
                     const struct stat *identity, struct stat *observed)
{
    char hash[65];
    struct stat st;
    if (!hash_fd(fd, hash, &st)) return 0;
    if (strcmp(hash, e->hash) || st.st_size != e->size) { errno = EBADMSG; return 0; }
    if ((metadata && !metadata_matches(&st, e)) || (identity && !same_inode(&st, identity))) {
        errno = ESTALE;
        return 0;
    }
    if (observed) *observed = st;
    return 1;
}

static int verify_file(const char *path, const Entry *e, int metadata,
                       const struct stat *identity, struct stat *observed)
{
    int fd = scoped_open(path, O_RDONLY);
    int ok, error;
    if (fd < 0) return fail("open-verify", path);
    ok = verify_fd(fd, e, metadata, identity, observed);
    error = errno;
    close(fd);
    errno = error;
    return ok ? 1 : fail("file-changed", path);
}

static int read_exact(int fd, void *data, size_t size)
{
    unsigned char *p = data;
    while (size) {
        ssize_t n = read(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EINVAL; return 0; }
        p += n;
        size -= (size_t)n;
    }
    return 1;
}

static int write_exact(int fd, const void *data, size_t size)
{
    const unsigned char *p = data;
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EIO; return 0; }
        p += n;
        size -= (size_t)n;
    }
    return 1;
}

static int read_u32(int fd, uint32_t *value)
{
    unsigned char b[4];
    if (!read_exact(fd, b, sizeof(b))) return 0;
    *value = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    return 1;
}

static int read_i64(int fd, int64_t *value)
{
    unsigned char b[8];
    uint64_t bits = 0;
    unsigned i;
    if (!read_exact(fd, b, sizeof(b))) return 0;
    for (i = 0; i < 8; ++i) bits |= (uint64_t)b[i] << (i * 8);
    if (bits > INT64_MAX) { errno = EINVAL; return 0; }
    *value = (int64_t)bits;
    return 1;
}

static size_t put_utf8(uint32_t cp, char *out)
{
    if (cp <= 0x7f) { out[0] = (char)cp; return 1; }
    if (cp <= 0x7ff) {
        out[0] = (char)(0xc0 | (cp >> 6)); out[1] = (char)(0x80 | (cp & 63));
        return 2;
    }
    if (cp <= 0xffff) {
        out[0] = (char)(0xe0 | (cp >> 12)); out[1] = (char)(0x80 | ((cp >> 6) & 63));
        out[2] = (char)(0x80 | (cp & 63)); return 3;
    }
    out[0] = (char)(0xf0 | (cp >> 18)); out[1] = (char)(0x80 | ((cp >> 12) & 63));
    out[2] = (char)(0x80 | ((cp >> 6) & 63)); out[3] = (char)(0x80 | (cp & 63));
    return 4;
}

static char *read_text(int fd)
{
    uint32_t units, i;
    unsigned char *raw;
    char *out;
    size_t used = 0;
    if (!read_u32(fd, &units) || units > MAX_TEXT) { errno = EINVAL; return NULL; }
    raw = calloc((size_t)units + 1, 2);
    out = calloc((size_t)units * 4 + 1, 1);
    if (!raw || !out || !read_exact(fd, raw, (size_t)units * 2)) goto bad;
    for (i = 0; i < units; ++i) {
        uint32_t cp = (uint32_t)raw[i * 2] | ((uint32_t)raw[i * 2 + 1] << 8);
        if (!cp) goto bad;
        if (cp >= 0xd800 && cp <= 0xdbff) {
            uint32_t low;
            if (++i >= units) goto bad;
            low = (uint32_t)raw[i * 2] | ((uint32_t)raw[i * 2 + 1] << 8);
            if (low < 0xdc00 || low > 0xdfff) goto bad;
            cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) goto bad;
        used += put_utf8(cp, out + used);
    }
    free(raw);
    return out;
bad:
    free(raw);
    free(out);
    errno = EINVAL;
    return NULL;
}

static int read_count(int fd, uint32_t *count)
{
    if (!read_u32(fd, count) || *count > budget) { *count = 0; errno = EINVAL; return 0; }
    budget -= *count;
    return 1;
}

static int read_entries(int fd, Entry **items, uint32_t *count)
{
    uint32_t i;
    if (!read_count(fd, count)) return 0;
    *items = calloc(*count ? *count : 1, sizeof(**items));
    if (!*items) return 0;
    for (i = 0; i < *count; ++i) {
        Entry *e = *items + i;
        if (!read_u32(fd, &e->kind) || !(e->path = read_text(fd))
            || !(e->saved = read_text(fd)) || !(e->hash = read_text(fd))
            || !read_u32(fd, &e->attributes) || !read_i64(fd, &e->time)
            || !read_i64(fd, &e->size) || !read_u32(fd, &e->children)
            || e->kind > 3 || e->attributes > 0777 || e->children > MAX_ITEMS)
            return reject("invalid-record", e->path, EINVAL);
    }
    return 1;
}

static int read_paths(int fd, char ***items, uint32_t *count)
{
    uint32_t i;
    if (!read_count(fd, count)) return 0;
    *items = calloc(*count ? *count : 1, sizeof(**items));
    if (!*items) return 0;
    for (i = 0; i < *count; ++i) if (!((*items)[i] = read_text(fd))) return 0;
    return 1;
}

static int load_plan(int fd)
{
    unsigned char magic[8], extra;
    uint32_t i;
    ssize_t tail;
    if (!read_exact(fd, magic, sizeof(magic)) || memcmp(magic, "OC2MAC1\0", 8)
        || !read_u32(fd, &plan.pid) || !plan.pid || plan.pid > INT_MAX
        || !read_i64(fd, &plan.creation) || !read_u32(fd, &plan.cleanup) || plan.cleanup > 1
        || !(plan.cache_boundary = read_text(fd)) || !(plan.plugin_boundary = read_text(fd))
        || !(plan.plugins = read_text(fd)) || !(plan.cache = read_text(fd))
        || !(plan.current = read_text(fd)) || !read_count(fd, &plan.count))
        return reject("invalid-mac-plan", home, EINVAL);
    plan.groups = calloc(plan.count ? plan.count : 1, sizeof(*plan.groups));
    if (!plan.groups) return 0;
    for (i = 0; i < plan.count; ++i) {
        Group *g = plan.groups + i;
        if (!read_entries(fd, &g->checks, &g->nc) || !read_entries(fd, &g->moves, &g->nm)
            || !read_entries(fd, &g->installs, &g->ni)
            || !read_paths(fd, &g->directories, &g->nd) || !read_paths(fd, &g->prune, &g->np)) return 0;
    }
    do { tail = read(fd, &extra, 1); } while (tail < 0 && errno == EINTR);
    return tail == 0 ? 1 : reject("plan-trailing-data", home, EINVAL);
}

static int valid_hash(const char *hash)
{
    size_t i;
    if (strlen(hash) != 64) return 0;
    for (i = 0; i < 64; ++i)
        if (!((hash[i] >= '0' && hash[i] <= '9') || (hash[i] >= 'a' && hash[i] <= 'f'))) return 0;
    return 1;
}

static int plugin_path(const char *path)
{
    return clean(path) && within(path, plan.plugins) && strcmp(path, plan.plugins);
}

static int validate_plan(void)
{
    uint32_t i, j;
    if (!clean(plan.cache_boundary) || !clean(plan.plugin_boundary) || !clean(plan.plugins) || !clean(plan.cache)
        || !within(plan.plugins, plan.plugin_boundary) || !within(plan.cache, plan.cache_boundary)
        || within(plan.plugins, plan.cache) || within(plan.cache, plan.plugins)
        || !within(home, plan.cache) || !strcmp(home, plan.cache) || !plugin_path(plan.current))
        return reject("invalid-roots", home, EPERM);
    if (!boundary_init(&cb, plan.cache_boundary) || !boundary_init(&pb, plan.plugin_boundary)) return 0;
    /* Overlapping boundaries must also pass the OUTER no-follow walk. */
    {
        Boundary *outer = &cb, *inner = &pb;
        Parent p;
        struct stat st;
        int ok;
        if (within(outer->path, inner->path)) { outer = &pb; inner = &cb; }
        if (strcmp(outer->path, inner->path) && within(inner->path, outer->path)) {
            if (!walk(outer, inner->path, 0, &p)) return 0;
            ok = fstatat(p.fd, p.name, &st, AT_SYMLINK_NOFOLLOW) == 0
                && S_ISDIR(st.st_mode) && same_inode(&st, &inner->identity);
            close(p.fd);
            if (!ok) return reject("nested-boundary-link", inner->path, EPERM);
        }
    }
    if (!validate_path(plan.plugins, 0) || !validate_path(plan.cache, 0)
        || !validate_path(home, 0) || !validate_path(plan.current, 1)) return 0;
    for (i = 0; i < plan.count; ++i) {
        Group *g = plan.groups + i;
        Entry *lists[3] = { g->checks, g->moves, g->installs };
        uint32_t counts[3] = { g->nc, g->nm, g->ni };
        unsigned k;
        for (k = 0; k < 3; ++k) for (j = 0; j < counts[k]; ++j) {
            Entry *e = lists[k] + j;
            if ((k && !plugin_path(e->path)) || !validate_path(e->path, k != 0)) return 0;
            if (k && e->kind > 1) return reject("operation-not-file", e->path, EINVAL);
            if (e->kind == 1 || k) {
                if (!clean(e->saved) || !within(e->saved, home) || !strcmp(e->saved, home)
                    || !valid_hash(e->hash) || !validate_path(e->saved, 0))
                    return reject("invalid-file-record", e->path, EINVAL);
            }
        }
        for (j = 0; j < g->nd; ++j)
            if (!plugin_path(g->directories[j]) || !validate_path(g->directories[j], 1)) return 0;
        for (j = 0; j < g->np; ++j)
            if (!plugin_path(g->prune[j]) || !validate_path(g->prune[j], 1)) return 0;
    }
    return 1;
}

static int metadata_name(const char *name, const struct stat *st)
{
    return !strcmp(name, ".DS_Store") && S_ISREG(st->st_mode);
}

static int directory_count(const char *path, uint32_t *count)
{
    int fd = scoped_open(path, O_RDONLY | O_DIRECTORY);
    DIR *dir;
    struct dirent *item;
    int error = 0;
    *count = 0;
    if (fd < 0) return fail("open-inventory", path);
    dir = fdopendir(fd);
    if (!dir) { error = errno; close(fd); return reject("fdopendir", path, error); }
    for (;;) {
        struct stat st;
        errno = 0;
        item = readdir(dir);
        if (!item) { error = errno; break; }
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
        if (fstatat(fd, item->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) { error = errno; break; }
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) { error = EINVAL; break; }
        if (within(path, plan.plugins) && metadata_name(item->d_name, &st)) continue;
        if (++*count > MAX_ITEMS) { error = EOVERFLOW; break; }
    }
    closedir(dir);
    return error ? reject("inventory-failed", path, error) : 1;
}

/* Takes ownership of fd. Only ordinary metadata/empty directories may remain. */
static int metadata_only_tree(int fd, unsigned depth, uint32_t *remaining)
{
    DIR *dir;
    struct dirent *item;
    int ok = 1;
    if (depth > 128) { close(fd); errno = EOVERFLOW; return 0; }
    dir = fdopendir(fd);
    if (!dir) { int error = errno; close(fd); errno = error; return 0; }
    for (;;) {
        struct stat st;
        errno = 0;
        item = readdir(dir);
        if (!item) { if (errno) ok = 0; break; }
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
        if (!*remaining) { errno = EOVERFLOW; ok = 0; break; }
        --*remaining;
        if (fstatat(fd, item->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) { ok = 0; break; }
        if (metadata_name(item->d_name, &st)) continue;
        if (!strcmp(item->d_name, ".DS_Store")) { errno = EINVAL; ok = 0; break; }
        if (S_ISDIR(st.st_mode)) {
            struct stat opened;
            int child = openat(fd, item->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0) { ok = 0; break; }
            if (fstat(child, &opened) != 0 || !same_inode(&st, &opened)) {
                close(child); errno = ESTALE; ok = 0; break;
            }
            if (metadata_only_tree(child, depth + 1, remaining)) continue;
        } else errno = ENOTEMPTY;
        ok = 0;
        break;
    }
    { int error = errno; closedir(dir); errno = error; }
    return ok;
}

static int check_entry(const Entry *e)
{
    struct stat st;
    uint32_t count;
    /* Finder metadata may change after approval. Never move or reject an
     * ordinary plugin metadata file, but a link/directory with that name blocks. */
    if (e->kind == 1 && within(e->path, plan.plugins)
        && !strcmp(strrchr(e->path, '/') + 1, ".DS_Store")) {
        if (!path_stat(e->path, &st)) return errno == ENOENT ? 1 : fail("metadata-stat", e->path);
        return S_ISREG(st.st_mode) ? 1 : reject("metadata-not-file", e->path, EINVAL);
    }
    if (!e->kind) return missing(e->path);
    if (e->kind == 1) return verify_file(e->saved, e, 0, NULL, NULL) && verify_file(e->path, e, 1, NULL, NULL);
    if (!path_stat(e->path, &st)) return fail("check-directory", e->path);
    if (!S_ISDIR(st.st_mode)) return reject("expected-directory", e->path, ENOTDIR);
    if (e->kind == 3) return 1;
    if (!directory_count(e->path, &count)) return 0;
    return count == e->children ? 1 : reject("inventory-changed", e->path, ESTALE);
}

/* There is no Darwin compare-inode-and-rename primitive. Check the pinned
 * source/name/parents before rename and the moved inode afterwards. Races
 * remain retained conflicts; no recovery destination may be overwritten. */
static int relocate(const char *from, const char *to, const Entry *e,
                    const struct stat *identity, int *did_move)
{
    Parent source = { .fd = -1 }, target = { .fd = -1 };
    struct stat opened, named;
    int fd = -1, ok = 0, error;
    *did_move = 0;
    if (!parent_for(from, 1, &source) || !parent_for(to, 1, &target)) goto done;
    fd = openat(source.fd, source.name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || !verify_fd(fd, e, 1, identity, &opened)) goto done;
    if (!parent_current(from, &source) || !parent_current(to, &target)) goto done;
    if (fstatat(source.fd, source.name, &named, AT_SYMLINK_NOFOLLOW) != 0) goto done;
    if (!same_state(&opened, &named)) { errno = ESTALE; goto done; }
    log_line("Debug", "intent=rename-exclusive source=\"%s\" target=\"%s\"", from, to);
    if (log_failed) { errno = EIO; goto done; }
    if (renameatx_np(source.fd, source.name, target.fd, target.name, RENAME_EXCL) != 0) goto done;
    *did_move = 1;
    log_line("Debug", "renamed source=\"%s\" target=\"%s\" recovery-copy-retained=true", from, to);
    if (fsync(source.fd) != 0 || fsync(target.fd) != 0) goto done;
    if (fstatat(target.fd, target.name, &named, AT_SYMLINK_NOFOLLOW) != 0) goto done;
    if (!same_inode(&opened, &named) || !metadata_matches(&named, e)) { errno = ESTALE; goto done; }
    if (!parent_current(to, &target) || !verify_fd(fd, e, 1, &opened, NULL)) goto done;
    ok = 1;
done:
    error = errno;
    if (fd >= 0) close(fd);
    if (source.fd >= 0) close(source.fd);
    if (target.fd >= 0) close(target.fd);
    errno = error;
    return ok ? 1 : fail("rename-exclusive", from);
}

static int set_metadata(int fd, const Entry *e, const struct stat *source)
{
    struct timeval times[2];
    struct timespec precise[2];
    int64_t seconds = e->time / TICKS - WINDOWS_EPOCH;
    precise[0] = source->st_atimespec;
    precise[1].tv_sec = (time_t)seconds;
    precise[1].tv_nsec = (long)((e->time % TICKS) * 100);
    if ((int64_t)precise[1].tv_sec != seconds) { errno = EOVERFLOW; return 0; }
    times[0].tv_sec = precise[0].tv_sec;
    times[0].tv_usec = (suseconds_t)(precise[0].tv_nsec / 1000);
    times[1].tv_sec = precise[1].tv_sec;
    times[1].tv_usec = (suseconds_t)(precise[1].tv_nsec / 1000);
    if (fchmod(fd, (mode_t)e->attributes) != 0 || futimes(fd, times) != 0) return 0;
    /* futimes is microsecond-only. futimens (10.13+) preserves FILETIME's
     * remaining fraction on APFS. Never cast timeval to timespec. */
    if (precise[1].tv_nsec % 1000 && futimens(fd, precise) != 0) return 0;
    return fsync(fd) == 0;
}

static int copy_install(const Entry *e, const char *temporary, Owned *owned)
{
    Parent p = { .fd = -1 };
    int in = -1, out = -1, ok = 0, error;
    struct stat source, named;
    unsigned char buffer[65536];
    ssize_t n;
    owned->present = 0;
    in = scoped_open(e->saved, O_RDONLY);
    if (in < 0 || !verify_fd(in, e, 0, NULL, &source)) goto done;
    if (!parent_for(temporary, 1, &p) || !parent_current(temporary, &p)) goto done;
    log_line("Debug", "intent=copy source=\"%s\" temporary=\"%s\" target=\"%s\"", e->saved, temporary, e->path);
    if (log_failed) { errno = EIO; goto done; }
    out = openat(p.fd, p.name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) goto done;
    owned->present = 1;
    if (fstat(out, &owned->identity) != 0 || lseek(in, 0, SEEK_SET) < 0) goto done;
    for (;;) {
        n = read(in, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto done;
        if (!n) break;
        if (!write_exact(out, buffer, (size_t)n)) goto done;
    }
    if (!verify_fd(in, e, 0, &source, NULL) || !set_metadata(out, e, &source)
        || !verify_fd(out, e, 1, &owned->identity, &owned->identity)) goto done;
    if (!parent_current(temporary, &p) || fstatat(p.fd, p.name, &named, AT_SYMLINK_NOFOLLOW) != 0) goto done;
    if (!same_state(&named, &owned->identity)) { errno = ESTALE; goto done; }
    if (fsync(p.fd) != 0) goto done;
    ok = 1;
done:
    error = errno;
    if (in >= 0) close(in);
    if (out >= 0 && close(out) != 0 && ok) { ok = 0; error = errno; }
    if (p.fd >= 0) close(p.fd);
    errno = error;
    if (!ok) {
        fail("copy-install", temporary);
        if (owned->present) log_line("Warning", "partial-file-retained path=\"%s\" inspect-before-removal=true", temporary);
    }
    return ok;
}

static int recovery_name(char path[PATH_MAX], const char *prefix, uint32_t group, uint32_t index)
{
    char leaf[80];
    int n = snprintf(leaf, sizeof(leaf), "%s-%08" PRIx32 "-%08" PRIx32, prefix, group, index);
    if (n < 0 || n >= (int)sizeof(leaf)) return reject("recovery-name", home, ENAMETOOLONG);
    return join(path, home, leaf);
}

static int prune_directory(const char *path)
{
    Parent p;
    struct stat st;
    int result, error;
    if (!parent_for(path, 1, &p)) return errno == ENOENT;
    if (fstatat(p.fd, p.name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        error = errno; close(p.fd);
        return error == ENOENT ? 1 : reject("prune-stat", path, error);
    }
    if (!S_ISDIR(st.st_mode)) { close(p.fd); return reject("prune-not-directory", path, ENOTDIR); }
    log_line("Debug", "intent=prune-empty-directory path=\"%s\"", path);
    if (log_failed) { close(p.fd); return reject("journal-failed", path, EIO); }
    /* unlinkat(AT_REMOVEDIR) cannot follow a replaced final symlink. */
    result = parent_current(path, &p) ? unlinkat(p.fd, p.name, AT_REMOVEDIR) : -1;
    error = errno;
    if (result == 0) {
        result = fsync(p.fd);
        error = errno;
        close(p.fd);
        return result == 0 ? 1 : reject("prune-flush", path, error);
    }
    if (error == ENOTEMPTY || error == EEXIST) {
        uint32_t remaining = MAX_ITEMS;
        int fd = openat(p.fd, p.name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat opened;
        int metadata_only = 0;
        if (fd >= 0) {
            if (fstat(fd, &opened) == 0 && same_inode(&st, &opened))
                metadata_only = metadata_only_tree(fd, 0, &remaining);
            else close(fd);
        }
        close(p.fd);
        if (metadata_only) {
            log_line("Debug", "keep-metadata-only-directory path=\"%s\" ordinary-.DS_Store-preserved=true", path);
            return 1;
        }
        if (!plan.cleanup) {
            /* A version folder may still contain the newly installed DLL or
             * unrelated player files. File commit is valid; never delete it. */
            log_line("Warning", "keep-nonempty-version-directory path=\"%s\" files-committed=true", path);
            return 1;
        }
        return reject("prune-nonempty-retained", path, ENOTEMPTY);
    }
    close(p.fd);
    return error == ENOENT ? 1 : reject("prune-failed", path, error);
}

static int run_group(Group *g, uint32_t number)
{
    Owned *moved = calloc(g->nm ? g->nm : 1, sizeof(*moved));
    Owned *installed = calloc(g->ni ? g->ni : 1, sizeof(*installed));
    uint32_t i;
    int ok = 0, incomplete = 0, original_error;
    char backup[PATH_MAX], temporary[PATH_MAX], parent[PATH_MAX], failed[PATH_MAX];
    if (!moved || !installed) { fail("allocate-transaction", home); goto done; }
    stage = "preflight";
    log_line("Debug", "group=%" PRIu32 " checks=%" PRIu32 " moves=%" PRIu32 " installs=%" PRIu32,
             number, g->nc, g->nm, g->ni);
    for (i = 0; i < g->nc; ++i) if (!check_entry(g->checks + i)) goto done;
    for (i = 0; i < g->ni; ++i)
        if (!verify_file(g->installs[i].saved, g->installs + i, 0, NULL, NULL)) goto done;
    stage = "backup";
    for (i = 0; i < g->nm; ++i) {
        Entry *e = g->moves + i;
        struct stat st;
        int optional = plan.cleanup && e->kind == 1;
        int did_move;
        if (path_stat(e->path, &st)) {
            if (metadata_name(strrchr(e->path, '/') + 1, &st)) {
                log_line("Debug", "keep-ordinary-metadata-file path=\"%s\"", e->path);
                continue;
            }
        } else if (optional && errno == ENOENT) {
            log_line("Debug", "cleanup-file-already-missing path=\"%s\"", e->path);
            continue;
        }
        if (!verify_file(e->saved, e, 0, NULL, NULL) || !verify_file(e->path, e, 1, NULL, &moved[i].identity)) {
            if (!optional) goto rollback;
            incomplete = 1;
            log_line("Warning", "keep-modified-cleanup-file path=\"%s\"", e->path);
            continue;
        }
        if (!recovery_name(backup, "rollback", number, i)) goto rollback;
        log_line("Debug", "backup-map original=\"%s\" snapshot=\"%s\" backup=\"%s\" sha256=%s mode=%" PRIu32 " mtime=%" PRId64,
                 e->path, e->saved, backup, e->hash, e->attributes, e->time);
        ok = relocate(e->path, backup, e, &moved[i].identity, &did_move);
        moved[i].present = did_move;
        if (!ok) goto rollback;
    }
    stage = "install";
    for (i = 0; i < g->nd; ++i) if (!make_directory(g->directories[i])) goto rollback;
    for (i = 0; i < g->ni; ++i) {
        Entry *e = g->installs + i;
        Owned temporary_owned = {0};
        int did_move, n;
        strcpy(parent, e->path);
        *strrchr(parent, '/') = '\0';
        if (!make_directory(parent) || !missing(e->path)) goto rollback;
        n = snprintf(temporary, sizeof(temporary), "%s.oc2-%08lx-%08" PRIx32 "-%08" PRIx32 ".tmp",
                     e->path, (unsigned long)getpid(), number, i);
        if (n < 0 || n >= (int)sizeof(temporary)) { reject("temporary-length", e->path, ENAMETOOLONG); goto rollback; }
        if (!copy_install(e, temporary, &temporary_owned)) goto rollback;
        installed[i].identity = temporary_owned.identity;
        ok = relocate(temporary, e->path, e, &installed[i].identity, &did_move);
        installed[i].present = did_move;
        if (!ok) {
            if (!did_move) log_line("Warning", "verified-temporary-retained path=\"%s\"", temporary);
            goto rollback;
        }
    }
    /* File commit is complete; maintenance failure is reported, not rolled back. */
    stage = "prune";
    for (i = 0; i < g->np; ++i) if (!prune_directory(g->prune[i])) incomplete = 1;
    ok = !incomplete;
    if (incomplete) reject("maintenance-incomplete", home, ESTALE);
    log_line("Debug", "group=%" PRIu32 " files-committed=true maintenance-complete=%d backups-retained=true", number, ok);
    goto done;
rollback:
    original_error = errno ? errno : EIO;
    stage = "rollback";
    log_line("Warning", "group=%" PRIu32 " original-error=%d restore-only-owned-bytes=true", number, original_error);
    for (i = g->ni; i > 0; --i) {
        Entry *e = g->installs + i - 1;
        int did_move;
        if (!installed[i - 1].present) continue;
        if (!verify_file(e->path, e, 1, &installed[i - 1].identity, NULL)) {
            log_line("Warning", "keep-concurrent-edit path=\"%s\" rollback-blocked=true", e->path);
            continue;
        }
        if (!recovery_name(failed, "failed-new", number, i - 1)
            || !relocate(e->path, failed, e, &installed[i - 1].identity, &did_move))
            log_line("Warning", "rollback-new-file-retained path=\"%s\"", e->path);
    }
    for (i = g->nm; i > 0; --i) {
        Entry *e = g->moves + i - 1;
        int did_move;
        if (!moved[i - 1].present) continue;
        if (!recovery_name(backup, "rollback", number, i - 1) || !missing(e->path)
            || !verify_file(e->saved, e, 0, NULL, NULL)
            || !verify_file(backup, e, 1, &moved[i - 1].identity, NULL)) {
            log_line("Warning", "restore-blocked original=\"%s\" backup-retained=true", e->path);
            continue;
        }
        strcpy(parent, e->path);
        *strrchr(parent, '/') = '\0';
        if (!make_directory(parent) || !relocate(backup, e->path, e, &moved[i - 1].identity, &did_move))
            log_line("Warning", "rollback-incomplete original=\"%s\" inspect-retained-backup=true", e->path);
    }
    errno = original_error;
    ok = 0;
done:
    free(moved);
    free(installed);
    return ok;
}

static int marker(const char *name, const char *expected)
{
    char path[PATH_MAX], bytes[128];
    struct stat before, after;
    int fd, ok, error;
    size_t length = strlen(expected);
    if (!join(path, home, name)) return -1;
    fd = scoped_open(path, O_RDONLY);
    if (fd < 0) return errno == ENOENT ? 0 : (fail("open-marker", path), -1);
    ok = length <= sizeof(bytes) && fstat(fd, &before) == 0 && S_ISREG(before.st_mode)
        && before.st_size == (off_t)length && read_exact(fd, bytes, length)
        && fstat(fd, &after) == 0 && same_state(&before, &after) && !memcmp(bytes, expected, length);
    error = errno;
    close(fd);
    if (!ok) { reject("invalid-marker", path, error ? error : EINVAL); return -1; }
    return 1;
}

static int mark(const char *name, const char *text)
{
    char path[PATH_MAX], pending[NAME_MAX + 1];
    Parent p = { .fd = -1 };
    struct stat created, named;
    int fd = -1, ok = 0, error;
    int n = snprintf(pending, sizeof(pending), "%s.pending", name);
    if (log_failed) return reject("journal-failed", name, EIO);
    if (n < 0 || n >= (int)sizeof(pending) || !join(path, home, name) || !parent_for(path, 1, &p)) goto done;
    fd = openat(p.fd, pending, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 || !write_exact(fd, text, strlen(text)) || fsync(fd) != 0 || fstat(fd, &created) != 0) goto done;
    if (!parent_current(path, &p) || fstatat(p.fd, pending, &named, AT_SYMLINK_NOFOLLOW) != 0) goto done;
    if (!same_state(&created, &named)) { errno = ESTALE; goto done; }
    if (renameatx_np(p.fd, pending, p.fd, p.name, RENAME_EXCL) != 0 || fsync(p.fd) != 0) goto done;
    ok = 1;
done:
    error = errno;
    if (fd >= 0 && close(fd) != 0 && ok) { ok = 0; error = errno; }
    if (p.fd >= 0) close(p.fd);
    errno = error;
    return ok ? 1 : fail("publish-marker", name);
}

static int owner_start(uint32_t pid, int64_t *ticks)
{
    struct proc_bsdinfo info;
    int n;
    if (!pid || pid > INT_MAX) { errno = EINVAL; return 0; }
    memset(&info, 0, sizeof(info));
    n = proc_pidinfo((int)pid, PROC_PIDTBSDINFO, 0, &info, (int)sizeof(info));
    if (n != (int)sizeof(info)) { if (n >= 0) errno = EIO; return 0; }
    if (info.pbi_start_tvsec > (uint64_t)(INT64_MAX / TICKS - WINDOWS_EPOCH - 1)
        || info.pbi_start_tvusec >= 1000000) { errno = EOVERFLOW; return 0; }
    *ticks = ((int64_t)info.pbi_start_tvsec + WINDOWS_EPOCH) * TICKS + (int64_t)info.pbi_start_tvusec * 10;
    return 1;
}

static int exact_owner(void)
{
    int64_t ticks;
    if (!owner_start(plan.pid, &ticks)) return fail("query-owner", home);
    return ticks == plan.creation ? 1 : reject("owner-pid-reused", home, ESTALE);
}

static int observe_owner(void)
{
    struct kevent change;
    int fd, error;
    if (!exact_owner()) return -1;
    fd = kqueue();
    if (fd < 0) { fail("kqueue", home); return -1; }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) goto bad;
    EV_SET(&change, (uintptr_t)plan.pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_ONESHOT, NOTE_EXIT, 0, NULL);
    if (kevent(fd, &change, 1, NULL, 0, NULL) < 0) goto bad;
    /* PID reuse or query failure during registration must precede ready. */
    if (!exact_owner()) goto bad;
    return fd;
bad:
    error = errno;
    close(fd);
    reject("register-exact-owner", home, error);
    return -1;
}

/* Only registered NOTE_EXIT proves exit. Query failure/ESRCH/EV_ERROR do not. */
static int owner_event(int fd, long timeout_ns)
{
    struct kevent event;
    struct timespec timeout = { 0, timeout_ns };
    int n = kevent(fd, NULL, 0, &event, 1, &timeout);
    if (n < 0) {
        if (errno == EINTR) return 0;
        fail("wait-owner-kevent", home);
        return -1;
    }
    if (!n) return 0;
    if ((event.flags & EV_ERROR) || event.ident != (uintptr_t)plan.pid
        || event.filter != EVFILT_PROC || !(event.fflags & NOTE_EXIT)) {
        reject("unexpected-owner-event", home, (event.flags & EV_ERROR) && event.data > 0 ? (int)event.data : EIO);
        return -1;
    }
    log_line("Debug", "exact-owner-exit-observed pid=%" PRIu32 " creation=%" PRId64, plan.pid, plan.creation);
    return 1;
}

static void restart_steam(void)
{
    char program[] = "/usr/bin/open", url[] = "steam://launch/728880";
    char *arguments[] = { program, url, NULL };
    pid_t child;
    int status = 0;
    int error = posix_spawn(&child, program, NULL, NULL, arguments, environ);
    if (error) { reject("spawn-steam-open", url, error); return; }
    /* Do not let a broken LaunchServices request keep this helper alive
     * forever. The fixed open process receives a bounded observation window. */
    {
        struct timespec began, now, delay = { 0, 100000000L };
        if (clock_gettime(CLOCK_MONOTONIC, &began) != 0) { fail("steam-open-clock", url); return; }
        for (;;) {
            pid_t observed = waitpid(child, &status, WNOHANG);
            if (observed == child) { error = 0; break; }
            if (observed < 0 && errno != EINTR) { error = errno; break; }
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) { error = errno; break; }
            if (now.tv_sec - began.tv_sec >= 15) {
                log_line("Warning", "steam-open-observation-timeout request-process-retained=true");
                return;
            }
            nanosleep(&delay, NULL);
        }
    }
    if (error || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        log_line("Warning", "steam-open-failed wait-error=%d status=%d installation-remains-successful=true", error, status);
        return;
    }
    log_line("Debug", "steam-restart-request-submitted=true not-proof-of-game-launch");
}

static int execute(void)
{
    struct timespec began, now;
    uint32_t i;
    int observer = observe_owner();
    int result = 4, event;
    if (observer < 0) return 3;
    if (!mark("started.flag", "Protocol 1; do not replay this plan. Inspect transaction logs and retained backups.\r\n")
        || !mark("ready.flag", "ready\r\n")) goto done;
    stage = "authorization";
    if (clock_gettime(CLOCK_MONOTONIC, &began) != 0) { fail("authorization-clock", home); goto done; }
    for (;;) {
        int grant;
        if (marker("cancel.flag", "cancel\r\n") != 0) { reject("authorization-cancelled", home, ECANCELED); goto done; }
        event = owner_event(observer, 0);
        if (event != 0 || !exact_owner()) { reject("owner-unavailable-before-authorization", home, ESRCH); goto done; }
        grant = marker("armed.flag", "armed\r\n");
        if (grant < 0) goto done;
        if (grant == 1) break;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) { fail("authorization-clock", home); goto done; }
        if (now.tv_sec - began.tv_sec >= 30) { reject("authorization-timeout", home, ETIMEDOUT); goto done; }
        event = owner_event(observer, 50000000L);
        if (event != 0) { reject("owner-ended-before-authorization", home, ESRCH); goto done; }
    }
    if (marker("cancel.flag", "cancel\r\n") != 0 || !exact_owner() || !mark("authorized.flag", "authorized\r\n")) goto done;
    result = 5;
    stage = "wait-game";
    log_line("Debug", "waiting-exact-owner pid=%" PRIu32 " creation=%" PRId64 " no-kill=true", plan.pid, plan.creation);
    for (;;) {
        if (marker("cancel.flag", "cancel\r\n") != 0) { reject("cancelled-before-owner-exit", home, ECANCELED); goto done; }
        event = owner_event(observer, 100000000L);
        if (event < 0) goto done;
        if (event == 1) break;
    }
    if (marker("cancel.flag", "cancel\r\n") != 0 || marker("armed.flag", "armed\r\n") != 1
        || marker("authorized.flag", "authorized\r\n") != 1) {
        reject("authorization-revoked", home, EPERM); goto done;
    }
    result = 6;
    for (i = 0; i < plan.count; ++i) if (!run_group(plan.groups + i, i)) goto done;
    stage = "complete";
    result = 7;
    if (!mark("complete.flag", "Applied successfully\r\n")) goto done;
    log_line("Info", "Applied successfully; protocol=OC2MAC1 cleanup=%" PRIu32 " recovery-copies-retained=true", plan.cleanup);
    if (log_failed) goto done;
    result = 0;
    if (!plan.cleanup) {
        char restart[PATH_MAX];
        struct stat st;
        if (join(restart, plan.cache, "restart.flag")) {
            if (path_stat(restart, &st)) {
                if (S_ISREG(st.st_mode)) restart_steam();
                else reject("restart-marker-not-file", restart, EINVAL);
            } else if (errno != ENOENT) fail("restart-marker", restart);
        }
    }
done:
    close(observer);
    return result;
}

static void free_entries(Entry *entries, uint32_t count)
{
    uint32_t i;
    if (!entries) return;
    for (i = 0; i < count; ++i) { free(entries[i].path); free(entries[i].saved); free(entries[i].hash); }
    free(entries);
}

static void free_paths(char **paths, uint32_t count)
{
    uint32_t i;
    if (!paths) return;
    for (i = 0; i < count; ++i) free(paths[i]);
    free(paths);
}

static void free_plan(void)
{
    uint32_t i;
    if (cb.fd >= 0) close(cb.fd);
    if (pb.fd >= 0) close(pb.fd);
    if (plan.groups) for (i = 0; i < plan.count; ++i) {
        Group *g = plan.groups + i;
        free_entries(g->checks, g->nc); free_entries(g->moves, g->nm); free_entries(g->installs, g->ni);
        free_paths(g->directories, g->nd); free_paths(g->prune, g->np);
    }
    free(plan.groups);
    free(plan.cache_boundary); free(plan.plugin_boundary); free(plan.plugins); free(plan.cache); free(plan.current);
}

static int query_metadata(const char *path)
{
    struct stat before, after;
    int64_t ticks;
    int fd, ok, error;
    /* Query mode never reads a plan. Steam ancestor mappings may resolve;
     * the final component must be an ordinary non-link file. */
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return 2;
    ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode)
        && filetime(before.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec, &ticks)
        && fstat(fd, &after) == 0 && same_state(&before, &after);
    error = errno;
    close(fd);
    errno = error;
    if (!ok) return 2;
    /* Decimal native permissions, one space, exact FILETIME, one newline. */
    return printf("%u %" PRId64 "\n", (unsigned)(before.st_mode & 0777), ticks) < 0 || fflush(stdout) != 0 ? 2 : 0;
}

static int query_owner(const char *text)
{
    char *end;
    unsigned long pid;
    int64_t ticks;
    const char *p;
    if (!*text) return 2;
    for (p = text; *p; ++p) if (*p < '0' || *p > '9') return 2;
    errno = 0;
    pid = strtoul(text, &end, 10);
    if (errno || *end || !pid || pid > INT_MAX || !owner_start((uint32_t)pid, &ticks)) return 2;
    return printf("%" PRId64 "\n", ticks) < 0 || fflush(stdout) != 0 ? 2 : 0;
}

static int detach(void)
{
    int fd, i, error;
    if (signal(SIGHUP, SIG_IGN) == SIG_ERR || signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 0;
    if (setsid() < 0 && getsid(0) != getpid()) return 0;
    fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (fd < 0) return 0;
    for (i = 0; i < 3; ++i) {
        if (dup2(fd, i) < 0 || fcntl(i, F_SETFD, 0) < 0) {
            error = errno; if (fd > 2) close(fd); errno = error; return 0;
        }
    }
    if (fd > 2) close(fd);
    umask(0077);
    return chdir("/") == 0;
}

static int executable_home(void)
{
    char executable[PATH_MAX];
    uint32_t size = (uint32_t)sizeof(executable);
    char *slash;
    /* realpath would erase evidence of forbidden links below the boundary. */
    if (_NSGetExecutablePath(executable, &size) != 0 || !clean(executable)) return 0;
    slash = strrchr(executable, '/');
    if (!slash || slash == executable) return 0;
    *slash = '\0';
    strcpy(home, executable);
    return 1;
}

int main(int argc, char **argv)
{
    char plan_path[PATH_MAX], log_path[PATH_MAX], initial_hash[65], current_hash[65];
    struct stat initial, parsed, current;
    int fd = -1, safe = -1, result = 2;
    if (argc == 3 && !strcmp(argv[1], "--metadata")) return query_metadata(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "--owner")) return query_owner(argv[2]);
    if (argc != 1 || !executable_home() || !detach() || !join(plan_path, home, "install.plan")) return 2;
    /* Bootstrap is read-only. Reopen the exact frozen plan via the boundary
     * walk before writing any log, marker or installation data. */
    fd = open(plan_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &initial) != 0 || !S_ISREG(initial.st_mode)
        || initial.st_size < 0 || (uint64_t)initial.st_size > MAX_PLAN_BYTES
        || !hash_fd(fd, initial_hash, &initial) || lseek(fd, 0, SEEK_SET) < 0
        || !load_plan(fd) || fstat(fd, &parsed) != 0 || !same_state(&initial, &parsed) || !validate_plan()) goto done;
    safe = scoped_open(plan_path, O_RDONLY);
    if (safe < 0 || !hash_fd(safe, current_hash, &current) || !same_state(&initial, &current)
        || strcmp(initial_hash, current_hash)) goto done;
    close(safe); safe = -1;
    close(fd); fd = -1;
    if (!join(log_path, home, plan.cleanup ? "cleanup-resources.log" : "apply.log")) goto done;
    {
        Parent p;
        struct stat st;
        if (!parent_for(log_path, 1, &p)) goto done;
        fd = openat(p.fd, p.name, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
        close(p.fd);
        if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) goto done;
        journal = fdopen(fd, "a");
        if (!journal) goto done;
        fd = -1;
    }
    log_line("Debug", "native-installer protocol=OC2MAC1 pid=%ld cleanup=%" PRIu32 " cache=\"%s\" detached=true",
             (long)getpid(), plan.cleanup, home);
    result = execute();
    if (result) log_line("Warning", "Installation aborted/incomplete exit-code=%d inspect-retained-cache-backups=true", result);
done:
    if (safe >= 0) close(safe);
    if (fd >= 0) close(fd);
    if (journal && fclose(journal) != 0 && !result) result = 7;
    free_plan();
    return result;
}
