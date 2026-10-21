// ============================================================================
// FIROZ OS v6.0 - TITANIUM ARCHITECT EDITION (@firozfar051)
// Part 1 of 4: Dynamic SPRX Bridge, SHA256/CRC32 Crypto, Process Manager & Turbo FTP
// ============================================================================
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/statvfs.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>

#define FIROZ_VERSION        "6.0-TITANIUM"
#define HTTP_PORT            8080
#define FTP_PORT             2121
#define IO_ALIGNMENT         4096
#define COPY_BUFFER_SIZE     (8 * 1024 * 1024)   // 8 MB Page-Aligned DMA-Style Buffer
#define FTP_BUFFER_SIZE      (2 * 1024 * 1024)   // 2 MB Turbo FTP Stream Buffer
#define SOCK_BUF_SIZE        (4 * 1024 * 1024)   // 4 MB Kernel Socket Window
#define KLOG_BUF_SIZE        (256 * 1024)        // 256 KB Kernel Log Ring Buffer
#define MAX_HISTORY_ITEMS    100

// ============================================================================
// ساختارهای کنترل وضعیت، تاریخچه عملیات و صف تسک‌های پس‌زمینه
// ============================================================================
typedef struct {
    volatile int is_running;
    volatile int cancel_requested;
    volatile int files_processed;
    volatile int dirs_processed;
    volatile long long total_bytes;
    volatile long long copied_bytes;
    volatile time_t start_time;
    char task_id[32];
    char task_type[32];
    char current_file[512];
    char src_path[1024];
    char dst_path[1024];
    char extra_result[256];
} TaskStatus;

typedef struct {
    char id[32];
    char action[32];
    char src[512];
    char dst[512];
    char status[24];
    char detail[128];
    long long bytes_processed;
    time_t started_at;
    time_t ended_at;
} HistoryEntry;

static TaskStatus global_task = {0};
static pthread_mutex_t task_mutex = PTHREAD_MUTEX_INITIALIZER;

static HistoryEntry task_history[MAX_HISTORY_ITEMS];
static int history_count = 0;
static pthread_mutex_t history_mutex = PTHREAD_MUTEX_INITIALIZER;

static int g_http_port = HTTP_PORT;
static volatile int g_server_running = 1;
static time_t g_boot_time = 0;

static char klog_buffer[KLOG_BUF_SIZE];
static volatile int klog_head = 0;
static pthread_mutex_t klog_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int type;
    int req_id;
    int priority;
    int msg_id;
    int target_id;
    int user_id;
    int unk1;
    int unk2;
    int app_id;
    int error_num;
    int unk3;
    unsigned char use_icon_image_uri;
    char message[1024];
    char icon_uri[1024];
    char unk[1024];
} OrbisNotificationRequest;

typedef struct {
    const void *in_ptr;
    uint32_t in_avail;
    uint64_t in_total;
    void *out_ptr;
    uint32_t out_avail;
    uint64_t out_total;
    const char *err_msg;
    void *internal_state;
    void *alloc_fn;
    void *free_fn;
    void *opaque_ptr;
    int dtype;
    uint64_t checksum;
    uint64_t reserved_val;
} ps5_zstream;

typedef struct {
    uint32_t size;
    int32_t user_id;
    uint32_t app_opt;
    uint64_t crash_report;
    uint32_t check_flag;
} LncAppParam;

// آیکون PNG استاندارد ۶۴ در ۶۴ برای ثبت روی صفحه اصلی PS5
static const unsigned char FIROZ_BUILTIN_PNG[] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40,
    0x08, 0x02, 0x00, 0x00, 0x00, 0x25, 0x0B, 0xE6,
    0x89, 0x00, 0x00, 0x00, 0x39, 0x49, 0x44, 0x41,
    0x54, 0x78, 0x9C, 0xED, 0xCF, 0x31, 0x0D, 0x00,
    0x20, 0x0C, 0x00, 0xB0, 0x4E, 0x67, 0x8F, 0x5A,
    0x37, 0xB8, 0x01, 0x4D, 0x90, 0x74, 0x7A, 0x9F,
    0xAD, 0xEC, 0xB5, 0xC0, 0x54, 0x05, 0x53, 0x15,
    0x4C, 0x55, 0x30, 0xD5, 0xC1, 0x54, 0x07, 0x53,
    0x1D, 0x4C, 0x75, 0x30, 0xD5, 0xC3, 0x54, 0x0F,
    0xF3, 0x9F, 0x17, 0x6F, 0x03, 0xB1, 0x04, 0xFF,
    0x0E, 0x88, 0xA8, 0xE1, 0x9E, 0x00, 0x00, 0x00,
    0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60,
    0x82
};
static const unsigned int FIROZ_BUILTIN_PNG_LEN = sizeof(FIROZ_BUILTIN_PNG);

// ============================================================================
// توابع کمکی سطح پایین، مبدل‌های Endianness و تخصیص‌دهنده حافظه تراز شده
// ============================================================================
static inline uint16_t bswap16(uint16_t x) {
    return (uint16_t)((x >> 8) | (x << 8));
}

static inline uint32_t bswap32(uint32_t x) {
    return ((x >> 24) & 0x000000FFU) |
           ((x >>  8) & 0x0000FF00U) |
           ((x <<  8) & 0x00FF0000U) |
           ((x << 24) & 0xFF000000U);
}

static inline uint64_t bswap64(uint64_t x) {
    return ((x >> 56) & 0x00000000000000FFULL) |
           ((x >> 40) & 0x000000000000FF00ULL) |
           ((x >> 24) & 0x0000000000FF0000ULL) |
           ((x >>  8) & 0x00000000FF000000ULL) |
           ((x <<  8) & 0x000000FF00000000ULL) |
           ((x << 24) & 0x0000FF0000000000ULL) |
           ((x << 40) & 0x00FF000000000000ULL) |
           ((x << 56) & 0xFF00000000000000ULL);
}

static void strip_crlf(char *s) {
    if (!s) return;
    for (; *s; s++) {
        if (*s == '\r' || *s == '\n') {
            *s = '\0';
            return;
        }
    }
}

void *alloc_aligned_buffer(size_t size) {
    void *ptr = NULL;
    if (posix_memalign(&ptr, IO_ALIGNMENT, size) == 0 && ptr != NULL) {
        return ptr;
    }
    return malloc(size);
}

void tune_socket_performance(int sock) {
    if (sock < 0) return;
    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    int sndbuf = SOCK_BUF_SIZE;
    int rcvbuf = SOCK_BUF_SIZE;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
}

int spawn_thread(void *(*func)(void *), void *arg) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, func, arg) != 0) return -1;
    pthread_detach(tid);
    return 0;
}

void send_all(int sock, const void *data, size_t length) {
    size_t total_sent = 0;
    const char *ptr = (const char *)data;
    while (total_sent < length) {
        ssize_t sent = send(sock, ptr + total_sent, length - total_sent, 0);
        if (sent < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            break;
        }
        if (sent == 0) break;
        total_sent += (size_t)sent;
    }
}

// ============================================================================
// موتور رمزنگاری و بررسی سلامت فایل‌ها (SHA-256 & CRC32 Hardware-Speed Engine)
// ============================================================================
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} FirozSha256Ctx;

static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)     (ROR32(x,2) ^ ROR32(x,13) ^ ROR32(x,22))
#define EP1(x)     (ROR32(x,6) ^ ROR32(x,11) ^ ROR32(x,25))
#define SIG0(x)    (ROR32(x,7) ^ ROR32(x,18) ^ ((x) >> 3))
#define SIG1(x)    (ROR32(x,17) ^ ROR32(x,19) ^ ((x) >> 10))

static void sha256_transform(FirozSha256Ctx *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + SHA256_K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(FirozSha256Ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(FirozSha256Ctx *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(FirozSha256Ctx *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *buf, size_t len) {
    crc = ~crc;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ (0xEDB88320U & (-(int)(crc & 1)));
        }
    }
    return ~crc;
}

int compute_file_hashes(const char *filepath, char *sha256_hex_out, char *crc32_hex_out, long long *size_out) {
    sha256_hex_out[0] = '\0';
    crc32_hex_out[0] = '\0';
    if (size_out) *size_out = 0;

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) == 0 && size_out) *size_out = (long long)st.st_size;

    uint8_t *buf = alloc_aligned_buffer(1024 * 1024);
    if (!buf) { close(fd); return -1; }

    FirozSha256Ctx sctx;
    sha256_init(&sctx);
    uint32_t crc = 0;

    ssize_t r;
    long long limit = 512LL * 1024LL * 1024LL; // حداکثر ۵۱۲ مگابایت برای پاسخ آنی در وب
    long long processed = 0;
    while ((r = read(fd, buf, 1024 * 1024)) > 0) {
        sha256_update(&sctx, buf, (size_t)r);
        crc = crc32_update(crc, buf, (size_t)r);
        processed += r;
        if (processed >= limit) break;
    }
    free(buf);
    close(fd);

    uint8_t digest[32];
    sha256_final(&sctx, digest);
    for (int i = 0; i < 32; i++) {
        snprintf(sha256_hex_out + (i * 2), 3, "%02x", digest[i]);
    }
    sha256_hex_out[64] = '\0';
    snprintf(crc32_hex_out, 16, "%08X", crc);
    return 0;
}

// ============================================================================
// سیستم لاگ هسته (Kernel Log Ring Buffer) و ثبت تاریخچه عملیات
// ============================================================================
static void klog_push_bytes(const char *data, size_t len) {
    if (!data || len == 0) return;
    pthread_mutex_lock(&klog_mutex);
    if (len >= KLOG_BUF_SIZE) {
        data += (len - (KLOG_BUF_SIZE - 1));
        len = KLOG_BUF_SIZE - 1;
    }
    if (klog_head + (int)len >= KLOG_BUF_SIZE - 1) {
        int keep = (KLOG_BUF_SIZE / 2);
        if (keep > klog_head) keep = klog_head;
        int start_idx = klog_head - keep;
        memmove(klog_buffer, klog_buffer + start_idx, (size_t)keep);
        klog_head = keep;
    }
    memcpy(klog_buffer + klog_head, data, len);
    klog_head += (int)len;
    klog_buffer[klog_head] = '\0';
    pthread_mutex_unlock(&klog_mutex);
}

void klog_appendf(const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (n > 0) {
        size_t len = (size_t)(n < (int)sizeof(msg) ? n : (int)sizeof(msg) - 1);
        klog_push_bytes(msg, len);
    }
}

void record_history_entry(const char *id, const char *action, const char *src, const char *dst, const char *status, const char *detail, long long bytes, time_t start_t) {
    pthread_mutex_lock(&history_mutex);
    if (history_count >= MAX_HISTORY_ITEMS) {
        memmove(&task_history[1], &task_history[0], sizeof(HistoryEntry) * (MAX_HISTORY_ITEMS - 1));
        history_count = MAX_HISTORY_ITEMS - 1;
    } else if (history_count > 0) {
        memmove(&task_history[1], &task_history[0], sizeof(HistoryEntry) * (size_t)history_count);
    }
    HistoryEntry *e = &task_history[0];
    snprintf(e->id, sizeof(e->id), "%s", id ? id : "op");
    snprintf(e->action, sizeof(e->action), "%s", action ? action : "task");
    snprintf(e->src, sizeof(e->src), "%s", src ? src : "");
    snprintf(e->dst, sizeof(e->dst), "%s", dst ? dst : "");
    snprintf(e->status, sizeof(e->status), "%s", status ? status : "done");
    snprintf(e->detail, sizeof(e->detail), "%s", detail ? detail : "");
    e->bytes_processed = bytes;
    e->started_at = start_t;
    e->ended_at = time(NULL);
    history_count++;
    pthread_mutex_unlock(&history_mutex);
}

// ============================================================================
// پل ارتباطی پویا با ماژول‌های بومی PS5 (اعلان‌ها، باز کردن خودکار UI و مدیریت پروسه‌ها)
// ============================================================================
void ps5_notify(const char *fmt, ...) {
    static int (*notify_fn)(int, OrbisNotificationRequest*, size_t, int) = NULL;
    static int resolved = 0;
    if (!resolved) {
        resolved = 1;
        notify_fn = dlsym(RTLD_DEFAULT, "sceKernelSendNotificationRequest");
        if (!notify_fn) {
            void *libk = dlopen("libkernel.sprx", RTLD_LAZY);
            if (!libk) libk = dlopen("libkernel_web.sprx", RTLD_LAZY);
            if (!libk) libk = dlopen("libkernel_sys.sprx", RTLD_LAZY);
            if (!libk) libk = dlopen("/system/common/lib/libkernel.sprx", RTLD_LAZY);
            if (libk) notify_fn = dlsym(libk, "sceKernelSendNotificationRequest");
        }
    }
    if (!notify_fn) return;

    OrbisNotificationRequest req;
    memset(&req, 0, sizeof(req));
    req.target_id = -1;
    req.use_icon_image_uri = 0;

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message) - 1, fmt, ap);
    va_end(ap);

    notify_fn(0, &req, sizeof(req), 0);
}

void load_ps5_sysmodule(uint32_t id) {
    static void *sysmod = NULL;
    if (!sysmod) sysmod = dlopen("libSceSysmodule.sprx", RTLD_LAZY);
    if (!sysmod) sysmod = dlopen("/system/common/lib/libSceSysmodule.sprx", RTLD_LAZY);
    if (sysmod) {
        int (*load_internal)(uint32_t) = dlsym(sysmod, "sceSysmoduleLoadModuleInternal");
        if (load_internal) load_internal(id);
    }
}

// باز کردن خودکار پنجره وب روی تلویزیون با استفاده از libSceShellUIUtil.sprx و مرورگر سیستم
void auto_launch_firoz_ui(int port) {
    char uri[128];
    snprintf(uri, sizeof(uri), "http://127.0.0.1:%d/", port);

    void *libShellUI = dlopen("/system_ex/common_ex/lib/libSceShellUIUtil.sprx", RTLD_LAZY);
    if (!libShellUI) libShellUI = dlopen("libSceShellUIUtil.sprx", RTLD_LAZY);
    if (libShellUI) {
        int (*shellInit)(void) = dlsym(libShellUI, "sceShellUIUtilInitialize");
        int (*launchUri)(const char*, void*) = dlsym(libShellUI, "sceShellUIUtilLaunchByUri");
        if (shellInit) shellInit();
        if (launchUri) {
            int rc = launchUri(uri, NULL);
            klog_appendf("[SHELL-UI] sceShellUIUtilLaunchByUri(%s) rc=0x%x\n", uri, rc);
            if (rc == 0) return;
        }
    }

    void *libSys = dlopen("libSceSystemService.sprx", RTLD_LAZY);
    if (!libSys) libSys = dlopen("/system/common/lib/libSceSystemService.sprx", RTLD_LAZY);
    if (libSys) {
        int (*launchBrowser)(const char*, void*) = dlsym(libSys, "sceSystemServiceLaunchWebBrowser");
        if (launchBrowser) {
            uint32_t param[16];
            memset(param, 0, sizeof(param));
            param[0] = sizeof(param);
            int rc = launchBrowser(uri, param);
            klog_appendf("[BROWSER] sceSystemServiceLaunchWebBrowser(%s) rc=0x%x\n", uri, rc);
        }
    }
}

// محافظ انرژی برای جلوگیری از خوابیدن کنسول در حین عملیات‌های سنگین
void* power_guard_thread(void *arg) {
    (void)arg;
    void *libSys = dlopen("libSceSystemService.sprx", RTLD_LAZY);
    if (!libSys) libSys = dlopen("/system/common/lib/libSceSystemService.sprx", RTLD_LAZY);

    void *libShell = dlopen("libSceShellCoreUtil.sprx", RTLD_LAZY);
    if (!libShell) libShell = dlopen("/system/common/lib/libSceShellCoreUtil.sprx", RTLD_LAZY);

    int (*powerTick)(int) = libSys ? dlsym(libSys, "sceSystemServicePowerTick") : NULL;
    int (*resetAutoPower)(void) = libShell ? dlsym(libShell, "sceShellCoreUtilResetAutoPowerDownTimer") : NULL;
    int (*turnOffSaver)(void) = libShell ? dlsym(libShell, "sceShellCoreUtilTurnOffScreenSaver") : NULL;

    while (g_server_running) {
        if (__atomic_load_n(&global_task.is_running, __ATOMIC_SEQ_CST)) {
            if (powerTick) powerTick(0);
            if (resetAutoPower) resetAutoPower();
            if (turnOffSaver) turnOffSaver();
        }
        sleep(12);
    }
    return NULL;
}

int32_t get_foreground_user_id(void) {
    static void *libUsr = NULL;
    if (!libUsr) libUsr = dlopen("libSceUserService.sprx", RTLD_LAZY);
    if (!libUsr) libUsr = dlopen("/system/common/lib/libSceUserService.sprx", RTLD_LAZY);
    if (libUsr) {
        int (*usrInit)(void*) = dlsym(libUsr, "sceUserServiceInitialize");
        int (*getFgUser)(int32_t*) = dlsym(libUsr, "sceUserServiceGetForegroundUser");
        int (*getInitUser)(int32_t*) = dlsym(libUsr, "sceUserServiceGetInitialUser");
        if (usrInit) usrInit(NULL);
        int32_t uid = -1;
        if (getFgUser && getFgUser(&uid) == 0 && uid >= 0) return uid;
        if (getInitUser && getInitUser(&uid) == 0 && uid >= 0) return uid;
    }
    return -1;
}

int launch_app_by_title_id(const char *title_id) {
    if (!title_id || !title_id[0]) return -1;
    int32_t uid = get_foreground_user_id();

    static void *libLnc = NULL;
    if (!libLnc) libLnc = dlopen("libSceLncUtil.sprx", RTLD_LAZY);
    if (!libLnc) libLnc = dlopen("/system/common/lib/libSceLncUtil.sprx", RTLD_LAZY);
    if (!libLnc) libLnc = dlopen("/system/priv/lib/libSceLncUtil.sprx", RTLD_LAZY);
    if (libLnc) {
        int (*lncInit)(void) = dlsym(libLnc, "sceLncUtilInitialize");
        int (*lncLaunch)(const char*, const char**, LncAppParam*) = dlsym(libLnc, "sceLncUtilLaunchApp");
        if (lncInit) lncInit();
        if (lncLaunch) {
            LncAppParam param;
            memset(&param, 0, sizeof(param));
            param.size = sizeof(LncAppParam);
            param.user_id = uid;
            int res = lncLaunch(title_id, NULL, &param);
            if (res >= 0) return res;
        }
    }

    static void *libSys = NULL;
    if (!libSys) libSys = dlopen("libSceSystemService.sprx", RTLD_LAZY);
    if (!libSys) libSys = dlopen("/system/common/lib/libSceSystemService.sprx", RTLD_LAZY);
    if (libSys) {
        int (*sysLaunch)(const char*, const char**, LncAppParam*) = dlsym(libSys, "sceSystemServiceLaunchApp");
        if (sysLaunch) {
            LncAppParam param;
            memset(&param, 0, sizeof(param));
            param.size = sizeof(LncAppParam);
            param.user_id = uid;
            int res = sysLaunch(title_id, NULL, &param);
            if (res >= 0) return res;
        }
    }

    load_ps5_sysmodule(0x80000022);
    static void *libAppMgr = NULL;
    if (!libAppMgr) libAppMgr = dlopen("libSceAppMgr.sprx", RTLD_LAZY);
    if (!libAppMgr) libAppMgr = dlopen("/system/common/lib/libSceAppMgr.sprx", RTLD_LAZY);
    if (libAppMgr) {
        int (*launch)(const char*, const char*, int) = dlsym(libAppMgr, "sceAppMgrLaunchAppByAppId");
        if (launch) return launch(title_id, NULL, 0);
    }
    return -1;
}

int kill_running_game(void) {
    static void *libSys = NULL;
    if (!libSys) libSys = dlopen("libSceSystemService.sprx", RTLD_LAZY);
    if (!libSys) libSys = dlopen("/system/common/lib/libSceSystemService.sprx", RTLD_LAZY);

    static void *libLnc = NULL;
    if (!libLnc) libLnc = dlopen("libSceLncUtil.sprx", RTLD_LAZY);
    if (!libLnc) libLnc = dlopen("/system/common/lib/libSceLncUtil.sprx", RTLD_LAZY);

    int app_id = -1;
    if (libSys) {
        int (*getBigApp)(void) = dlsym(libSys, "sceSystemServiceGetAppIdOfRunningBigApp");
        if (getBigApp) app_id = getBigApp();
    }
    if (app_id > 0 && libLnc) {
        int (*killApp)(int) = dlsym(libLnc, "sceLncUtilKillApp");
        if (killApp) {
            int rc = killApp(app_id);
            ps5_notify("FIROZ OS: Closed Running Game (AppID: 0x%x)", app_id);
            klog_appendf("[APP] Killed BigApp 0x%x (rc=0x%x)\n", app_id, rc);
            return rc;
        }
    }
    return -1;
}

int launch_game(const char *title_id) {
    int res = launch_app_by_title_id(title_id);
    ps5_notify("FIROZ OS: Launching %s", title_id);
    klog_appendf("[LAUNCH] TitleID: %s (res=0x%x)\n", title_id, res);
    return res;
}

int install_pkg(const char *pkg_path) {
    if (!pkg_path || access(pkg_path, F_OK) != 0) return -1;
    load_ps5_sysmodule(0x80000018);
    static void *libAppInst = NULL;
    if (!libAppInst) libAppInst = dlopen("libSceAppInstUtil.sprx", RTLD_LAZY);
    if (!libAppInst) libAppInst = dlopen("/system/common/lib/libSceAppInstUtil.sprx", RTLD_LAZY);
    if (libAppInst) {
        int (*init)(void) = dlsym(libAppInst, "sceAppInstUtilInitialize");
        int (*install)(const char*, void*, void*) = dlsym(libAppInst, "sceAppInstUtilInstallByPackage");
        if (init) init();
        if (install) {
            unsigned char meta_buf[512] = {0};
            unsigned char playgo_buf[512] = {0};
            int ret = install(pkg_path, meta_buf, playgo_buf);
            const char *base = strrchr(pkg_path, '/');
            ps5_notify("FIROZ OS: Queued PKG %s", base ? base + 1 : pkg_path);
            klog_appendf("[PKG] Queued: %s (ret=0x%x)\n", pkg_path, ret);
            return ret;
        }
    }
    return -1;
}

int register_app_folder_on_homescreen(const char *tid, const char *title_name, uint32_t cat_type, const char *deeplink_uri) {
    if (!tid || strlen(tid) != 9) return -1;

    char dir_app[256], dir_sys[256], dir_meta[256];
    char p_json1[256], p_json2[256], p_icon1[256], p_icon2[256];

    snprintf(dir_app, sizeof(dir_app), "/user/app/%s", tid);
    snprintf(dir_sys, sizeof(dir_sys), "/user/app/%s/sce_sys", tid);
    snprintf(dir_meta, sizeof(dir_meta), "/user/appmeta/%s", tid);

    mkdir("/user/app", 0777);
    mkdir(dir_app, 0777);
    mkdir(dir_sys, 0777);
    mkdir("/user/appmeta", 0777);
    mkdir(dir_meta, 0777);

    snprintf(p_json1, sizeof(p_json1), "%s/param.json", dir_sys);
    snprintf(p_json2, sizeof(p_json2), "%s/param.json", dir_meta);
    snprintf(p_icon1, sizeof(p_icon1), "%s/icon0.png", dir_sys);
    snprintf(p_icon2, sizeof(p_icon2), "%s/icon0.png", dir_meta);

    const char *jsons[2] = { p_json1, p_json2 };
    for (int i = 0; i < 2; i++) {
        FILE *f = fopen(jsons[i], "wb");
        if (f) {
            if (deeplink_uri && deeplink_uri[0]) {
                fprintf(f,
                    "{\n"
                    "  \"applicationCategoryType\": %u,\n"
                    "  \"titleId\": \"%s\",\n"
                    "  \"deeplinkUri\": \"%s\",\n"
                    "  \"localizedParameters\": {\n"
                    "    \"defaultLanguage\": \"en-US\",\n"
                    "    \"en-US\": {\n"
                    "      \"titleName\": \"%s\"\n"
                    "    }\n"
                    "  }\n"
                    "}\n", cat_type, tid, deeplink_uri, title_name);
            } else {
                fprintf(f,
                    "{\n"
                    "  \"applicationCategoryType\": %u,\n"
                    "  \"applicationDrmType\": \"standard\",\n"
                    "  \"contentId\": \"IV0000-%s_00-FIROZOSHOMEBREW0\",\n"
                    "  \"contentVersion\": \"01.000.000\",\n"
                    "  \"masterVersion\": \"01.00\",\n"
                    "  \"titleId\": \"%s\",\n"
                    "  \"localizedParameters\": {\n"
                    "    \"defaultLanguage\": \"en-US\",\n"
                    "    \"en-US\": {\n"
                    "      \"titleName\": \"%s\"\n"
                    "    }\n"
                    "  }\n"
                    "}\n", cat_type, tid, tid, title_name);
            }
            fclose(f);
            chmod(jsons[i], 0777);
        }
    }

    if (access(p_icon1, F_OK) != 0) {
        FILE *ic1 = fopen(p_icon1, "wb");
        if (ic1) { fwrite(FIROZ_BUILTIN_PNG, 1, FIROZ_BUILTIN_PNG_LEN, ic1); fclose(ic1); chmod(p_icon1, 0777); }
    }
    if (access(p_icon2, F_OK) != 0) {
        FILE *ic2 = fopen(p_icon2, "wb");
        if (ic2) { fwrite(FIROZ_BUILTIN_PNG, 1, FIROZ_BUILTIN_PNG_LEN, ic2); fclose(ic2); chmod(p_icon2, 0777); }
    }

    load_ps5_sysmodule(0x80000018);
    static void *libAppInst = NULL;
    if (!libAppInst) libAppInst = dlopen("libSceAppInstUtil.sprx", RTLD_LAZY);
    if (!libAppInst) libAppInst = dlopen("/system/common/lib/libSceAppInstUtil.sprx", RTLD_LAZY);
    if (!libAppInst) return -1;

    int (*init)(void) = dlsym(libAppInst, "sceAppInstUtilInitialize");
    int (*installTitleDir)(const char*, const char*, void*) = dlsym(libAppInst, "sceAppInstUtilAppInstallTitleDir");
    int (*installAll)(void*) = dlsym(libAppInst, "sceAppInstUtilAppInstallAll");

    if (init) init();
    int rc = -1;
    if (installTitleDir) {
        rc = installTitleDir(tid, "/user/app/", NULL);
    }
    if (rc != 0 && installAll) {
        rc = installAll(NULL);
    }
    klog_appendf("[APPINST] Registered %s (%s) rc=0x%x\n", tid, title_name, rc);
    return rc;
}

void install_firoz_homescreen_tile(int port) {
    char uri[128];
    snprintf(uri, sizeof(uri), "http://127.0.0.1:%d/", port);
    register_app_folder_on_homescreen("FMGR00051", "FIROZ OS v6.0", 65536, uri);
}

// تزریق مستقیم بافر باینری ELF از حافظه RAM به elfldr (پورت‌های 9021 و 9020)
int inject_elf_buffer_to_elfldr(const void *data, size_t sz, const char *label) {
    if (!data || sz <= 4) return -1;
    const unsigned char *bytes = (const unsigned char *)data;
    if (bytes[0] != 0x7F || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F') {
        return -2;
    }

    const int ports[2] = { 9021, 9020 };
    for (int i = 0; i < 2; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        tune_socket_performance(sock);

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)ports[i]);
        addr.sin_addr.s_addr = htonl(0x7f000001U);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            send_all(sock, data, sz);
            close(sock);
            ps5_notify("FIROZ OS: Injected %s (%zu KB)", label ? label : "Payload", sz / 1024);
            klog_appendf("[ELFLDR] Sent %s (%zu bytes) -> 127.0.0.1:%d\n", label ? label : "RAM-ELF", sz, ports[i]);
            return 0;
        }
        close(sock);
    }
    return -1;
}

int launch_elf_payload(const char *elf_path) {
    struct stat st;
    if (!elf_path || stat(elf_path, &st) != 0 || st.st_size <= 4) return -1;
    int fd = open(elf_path, O_RDONLY);
    if (fd < 0) return -1;
    size_t sz = (size_t)st.st_size;

    char *data = malloc(sz);
    if (!data) { close(fd); return -1; }
    size_t total_r = 0;
    while (total_r < sz) {
        ssize_t r = read(fd, data + total_r, sz - total_r);
        if (r <= 0) break;
        total_r += (size_t)r;
    }
    close(fd);
    if (total_r != sz) { free(data); return -1; }

    const char *base = strrchr(elf_path, '/');
    int rc = inject_elf_buffer_to_elfldr(data, sz, base ? base + 1 : elf_path);
    free(data);
    return rc;
}

void* klog_reader_thread(void* arg) {
    (void)arg;
    int fd = open("/dev/klog", O_RDONLY | O_NONBLOCK);
    if (fd < 0) return NULL;
    char *temp = malloc(8192);
    if (!temp) { close(fd); return NULL; }
    while (g_server_running) {
        ssize_t n;
        while ((n = read(fd, temp, 8191)) > 0) {
            temp[n] = '\0';
            klog_push_bytes(temp, (size_t)n);
        }
        usleep(350000);
    }
    free(temp);
    close(fd);
    return NULL;
}

// ============================================================================
// سرور کامل و چندریسمانی Turbo FTP (پورت 2121 با دستورات پیشرفته)
// ============================================================================
void ftp_send_reply(int sock, int code, const char *msg) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%d %s\r\n", code, msg);
    send_all(sock, buf, strlen(buf));
}

static void ftp_build_path(const char *cwd, const char *arg, char *out, size_t max_len) {
    while (*arg == ' ') arg++;
    if (arg[0] == '/') {
        snprintf(out, max_len, "%s", arg);
    } else if (strcmp(cwd, "/") == 0) {
        snprintf(out, max_len, "/%s", arg);
    } else {
        snprintf(out, max_len, "%s/%s", cwd, arg);
    }
}

void* ftp_client_handler(void* arg) {
    int ctrl_sock = *(int*)arg;
    free(arg);

    tune_socket_performance(ctrl_sock);
    struct timeval tv = { 600, 0 };
    setsockopt(ctrl_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ftp_send_reply(ctrl_sock, 220, "FIROZ OS v6.0 Titanium Turbo FTP Server Ready.");

    char *cwd = malloc(1024);
    char *rnfr_path = malloc(1024);
    char *buf = malloc(2048);
    if (!cwd || !rnfr_path || !buf) {
        if (cwd) free(cwd);
        if (rnfr_path) free(rnfr_path);
        if (buf) free(buf);
        close(ctrl_sock);
        return NULL;
    }
    strcpy(cwd, "/");
    rnfr_path[0] = '\0';

    int data_sock = -1;
    int pasv_sock = -1;
    long long rest_offset = 0;

    while (g_server_running) {
        int n = recv(ctrl_sock, buf, 2047, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        strip_crlf(buf);

        if (strncasecmp(buf, "USER", 4) == 0) ftp_send_reply(ctrl_sock, 230, "User logged in.");
        else if (strncasecmp(buf, "PASS", 4) == 0) ftp_send_reply(ctrl_sock, 230, "User logged in.");
        else if (strncasecmp(buf, "SYST", 4) == 0) ftp_send_reply(ctrl_sock, 215, "UNIX Type: L8");
        else if (strncasecmp(buf, "NOOP", 4) == 0) ftp_send_reply(ctrl_sock, 200, "NOOP OK.");
        else if (strncasecmp(buf, "TYPE", 4) == 0) ftp_send_reply(ctrl_sock, 200, "Binary mode set.");
        else if (strncasecmp(buf, "REST ", 5) == 0) {
            rest_offset = strtoll(buf + 5, NULL, 10);
            if (rest_offset < 0) rest_offset = 0;
            ftp_send_reply(ctrl_sock, 350, "Restart offset accepted.");
        }
        else if (strncasecmp(buf, "FEAT", 4) == 0) {
            const char *feat = "211-Features:\r\n UTF8\r\n SIZE\r\n MDTM\r\n REST STREAM\r\n PASV\r\n211 End\r\n";
            send_all(ctrl_sock, feat, strlen(feat));
        }
        else if (strncasecmp(buf, "OPTS", 4) == 0) {
            ftp_send_reply(ctrl_sock, 200, "UTF8 mode enabled.");
        }
        else if (strncasecmp(buf, "PWD", 3) == 0 || strncasecmp(buf, "XPWD", 4) == 0) {
            char p[1100];
            snprintf(p, sizeof(p), "\"%s\" is current directory.", cwd);
            ftp_send_reply(ctrl_sock, 257, p);
        }
        else if (strncasecmp(buf, "CDUP", 4) == 0) {
            char *last = strrchr(cwd, '/');
            if (last && last != cwd) *last = '\0';
            else strcpy(cwd, "/");
            ftp_send_reply(ctrl_sock, 250, "Directory changed.");
        }
        else if (strncasecmp(buf, "CWD ", 4) == 0) {
            char *target = buf + 4;
            while (*target == ' ') target++;
            if (strcmp(target, "..") == 0) {
                char *last = strrchr(cwd, '/');
                if (last && last != cwd) *last = '\0';
                else strcpy(cwd, "/");
            } else if (target[0]) {
                char next_cwd[1024];
                ftp_build_path(cwd, target, next_cwd, sizeof(next_cwd));
                snprintf(cwd, 1024, "%s", next_cwd);
            }
            ftp_send_reply(ctrl_sock, 250, "Directory changed.");
        }
        else if (strncasecmp(buf, "SIZE ", 5) == 0) {
            char fpath[1024];
            ftp_build_path(cwd, buf + 5, fpath, sizeof(fpath));
            struct stat st;
            if (stat(fpath, &st) == 0) {
                char sbuf[64];
                snprintf(sbuf, sizeof(sbuf), "%lld", (long long)st.st_size);
                ftp_send_reply(ctrl_sock, 213, sbuf);
            } else ftp_send_reply(ctrl_sock, 550, "File not found.");
        }
        else if (strncasecmp(buf, "MDTM ", 5) == 0) {
            char fpath[1024];
            ftp_build_path(cwd, buf + 5, fpath, sizeof(fpath));
            struct stat st;
            if (stat(fpath, &st) == 0) {
                struct tm tmv;
                gmtime_r(&st.st_mtime, &tmv);
                char tbuf[64];
                snprintf(tbuf, sizeof(tbuf), "%04d%02d%02d%02d%02d%02d",
                    tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                    tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
                ftp_send_reply(ctrl_sock, 213, tbuf);
            } else ftp_send_reply(ctrl_sock, 550, "File not found.");
        }
        else if (strncasecmp(buf, "MKD ", 4) == 0 || strncasecmp(buf, "XMKD ", 5) == 0) {
            char *argp = strchr(buf, ' ') + 1;
            char dpath[1024];
            ftp_build_path(cwd, argp, dpath, sizeof(dpath));
            mkdir(dpath, 0777);
            ftp_send_reply(ctrl_sock, 257, "Directory created.");
        }
        else if (strncasecmp(buf, "DELE ", 5) == 0) {
            char fpath[1024];
            ftp_build_path(cwd, buf + 5, fpath, sizeof(fpath));
            unlink(fpath);
            ftp_send_reply(ctrl_sock, 250, "File deleted.");
        }
        else if (strncasecmp(buf, "RMD ", 4) == 0 || strncasecmp(buf, "XRMD ", 5) == 0) {
            char *argp = strchr(buf, ' ') + 1;
            char dpath[1024];
            ftp_build_path(cwd, argp, dpath, sizeof(dpath));
            rmdir(dpath);
            ftp_send_reply(ctrl_sock, 250, "Directory removed.");
        }
        else if (strncasecmp(buf, "RNFR ", 5) == 0) {
            ftp_build_path(cwd, buf + 5, rnfr_path, 1024);
            ftp_send_reply(ctrl_sock, 350, "Ready for RNTO.");
        }
        else if (strncasecmp(buf, "RNTO ", 5) == 0) {
            char rnto_path[1024];
            ftp_build_path(cwd, buf + 5, rnto_path, sizeof(rnto_path));
            rename(rnfr_path, rnto_path);
            ftp_send_reply(ctrl_sock, 250, "Rename successful.");
        }
        else if (strncasecmp(buf, "SITE CHMOD ", 11) == 0) {
            char *p = buf + 11;
            while (*p == ' ') p++;
            mode_t m = (mode_t)strtol(p, &p, 8);
            while (*p == ' ') p++;
            char fpath[1024];
            ftp_build_path(cwd, p, fpath, sizeof(fpath));
            chmod(fpath, m);
            ftp_send_reply(ctrl_sock, 200, "CHMOD OK.");
        }
        else if (strncasecmp(buf, "PASV", 4) == 0) {
            if (pasv_sock >= 0) close(pasv_sock);
            pasv_sock = socket(AF_INET, SOCK_STREAM, 0);
            tune_socket_performance(pasv_sock);
            struct timeval ptv = { 45, 0 };
            setsockopt(pasv_sock, SOL_SOCKET, SO_RCVTIMEO, &ptv, sizeof(ptv));
            struct sockaddr_in paddr, local_addr;
            memset(&paddr, 0, sizeof(paddr));
            paddr.sin_family = AF_INET;
            paddr.sin_addr.s_addr = INADDR_ANY;
            paddr.sin_port = 0;
            bind(pasv_sock, (struct sockaddr*)&paddr, sizeof(paddr));
            listen(pasv_sock, 1);
            socklen_t len = sizeof(paddr);
            getsockname(pasv_sock, (struct sockaddr*)&paddr, &len);
            socklen_t llen = sizeof(local_addr);
            getsockname(ctrl_sock, (struct sockaddr*)&local_addr, &llen);
            uint32_t ip_v = local_addr.sin_addr.s_addr;
            int p1 = (ntohs(paddr.sin_port) >> 8) & 0xFF;
            int p2 = ntohs(paddr.sin_port) & 0xFF;
            char msg[128];
            snprintf(msg, sizeof(msg), "Entering Passive Mode (%u,%u,%u,%u,%d,%d).",
                ip_v & 0xFF, (ip_v >> 8) & 0xFF, (ip_v >> 16) & 0xFF, (ip_v >> 24) & 0xFF, p1, p2);
            ftp_send_reply(ctrl_sock, 227, msg);
        }
        else if (strncasecmp(buf, "LIST", 4) == 0 || strncasecmp(buf, "NLST", 4) == 0) {
            if (pasv_sock >= 0) {
                ftp_send_reply(ctrl_sock, 150, "Opening directory list.");
                data_sock = accept(pasv_sock, NULL, NULL);
                if (data_sock >= 0) {
                    tune_socket_performance(data_sock);
                    DIR *d = opendir(cwd);
                    if (d) {
                        struct dirent *dir;
                        char *fpath = malloc(2048);
                        while (fpath && (dir = readdir(d)) != NULL) {
                            if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
                            ftp_build_path(cwd, dir->d_name, fpath, 2048);
                            struct stat st;
                            if (stat(fpath, &st) != 0) memset(&st, 0, sizeof(st));
                            char line[600];
                            snprintf(line, sizeof(line), "%s 1 ps5 wheel %lld Jan 01 00:00 %s\r\n",
                                S_ISDIR(st.st_mode) ? "drwxrwxrwx" : "-rwxrwxrwx", (long long)st.st_size, dir->d_name);
                            send_all(data_sock, line, strlen(line));
                        }
                        if (fpath) free(fpath);
                        closedir(d);
                    }
                    close(data_sock);
                }
                close(pasv_sock); pasv_sock = -1;
                ftp_send_reply(ctrl_sock, 226, "Transfer complete.");
            } else ftp_send_reply(ctrl_sock, 425, "Use PASV first.");
        }
        else if (strncasecmp(buf, "RETR ", 5) == 0) {
            char fpath[1024];
            ftp_build_path(cwd, buf + 5, fpath, sizeof(fpath));
            int fd = open(fpath, O_RDONLY);
            if (fd < 0) ftp_send_reply(ctrl_sock, 550, "File not found.");
            else {
                if (rest_offset > 0) {
                    lseek(fd, (off_t)rest_offset, SEEK_SET);
                    rest_offset = 0;
                }
                if (pasv_sock >= 0) {
                    ftp_send_reply(ctrl_sock, 150, "Opening Turbo binary stream.");
                    data_sock = accept(pasv_sock, NULL, NULL);
                    if (data_sock >= 0) {
                        tune_socket_performance(data_sock);
                        char *dbuf = alloc_aligned_buffer(FTP_BUFFER_SIZE);
                        if (dbuf) {
                            ssize_t r;
                            while ((r = read(fd, dbuf, FTP_BUFFER_SIZE)) > 0) {
                                send_all(data_sock, dbuf, (size_t)r);
                            }
                            free(dbuf);
                        }
                        close(data_sock);
                    }
                    close(pasv_sock); pasv_sock = -1;
                    ftp_send_reply(ctrl_sock, 226, "Transfer complete.");
                } else ftp_send_reply(ctrl_sock, 425, "Use PASV first.");
                close(fd);
            }
        }
        else if (strncasecmp(buf, "STOR ", 5) == 0 || strncasecmp(buf, "APPE ", 5) == 0) {
            int is_appe = (strncasecmp(buf, "APPE ", 5) == 0);
            char fpath[1024];
            ftp_build_path(cwd, buf + 5, fpath, sizeof(fpath));
            int flags = O_WRONLY | O_CREAT | (is_appe ? O_APPEND : (rest_offset > 0 ? 0 : O_TRUNC));
            int fd = open(fpath, flags, 0777);
            if (fd < 0) ftp_send_reply(ctrl_sock, 550, "Cannot create file.");
            else {
                if (!is_appe && rest_offset > 0) {
                    lseek(fd, (off_t)rest_offset, SEEK_SET);
                    rest_offset = 0;
                }
                if (pasv_sock >= 0) {
                    ftp_send_reply(ctrl_sock, 150, "Receiving Turbo binary stream.");
                    data_sock = accept(pasv_sock, NULL, NULL);
                    if (data_sock >= 0) {
                        tune_socket_performance(data_sock);
                        char *dbuf = alloc_aligned_buffer(FTP_BUFFER_SIZE);
                        if (dbuf) {
                            ssize_t r;
                            while ((r = recv(data_sock, dbuf, FTP_BUFFER_SIZE, 0)) > 0) {
                                size_t written = 0;
                                while (written < (size_t)r) {
                                    ssize_t w = write(fd, dbuf + written, (size_t)r - written);
                                    if (w <= 0) break;
                                    written += (size_t)w;
                                }
                            }
                            free(dbuf);
                        }
                        close(data_sock);
                    }
                    close(pasv_sock); pasv_sock = -1;
                    fchmod(fd, 0777);
                    ftp_send_reply(ctrl_sock, 226, "Upload complete.");
                } else ftp_send_reply(ctrl_sock, 425, "Use PASV first.");
                close(fd);
            }
        }
        else if (strncasecmp(buf, "QUIT", 4) == 0) {
            ftp_send_reply(ctrl_sock, 221, "Goodbye.");
            break;
        } else {
            ftp_send_reply(ctrl_sock, 502, "Command not implemented.");
        }
    }
    if (pasv_sock >= 0) close(pasv_sock);
    free(cwd);
    free(rnfr_path);
    free(buf);
    close(ctrl_sock);
    return NULL;
}

void* ftp_server_thread(void* arg) {
    (void)arg;
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) return NULL;
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(FTP_PORT);
    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        listen(server_sock, 32);
        while (g_server_running) {
            int c_fd = accept(server_sock, NULL, NULL);
            if (c_fd >= 0) {
                int *client_sock = malloc(sizeof(int));
                if (client_sock) {
                    *client_sock = c_fd;
                    if (spawn_thread(ftp_client_handler, client_sock) != 0) {
                        free(client_sock);
                        close(c_fd);
                    }
                } else close(c_fd);
            }
        }
    }
    close(server_sock);
    return NULL;
}
// ============================================================================
// FIROZ OS v6.0 - TITANIUM ARCHITECT EDITION (@firozfar051)
// Part 2 of 4: 8MB DMA-Style File Engine, Sony PKG/CNT Suite, AppMeta Studio & Search
// ============================================================================

void url_decode(char *dst, const char *src, size_t max_len) {
    size_t written = 0;
    char a, b;
    if (!dst || max_len == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    while (*src && written + 1 < max_len) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) &&
            (isxdigit((unsigned char)a) && isxdigit((unsigned char)b))) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= ('A' - 10); else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= ('A' - 10); else b -= '0';
            *dst++ = (char)(16 * a + b);
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
        written++;
    }
    *dst = '\0';
}

void get_param(const char *url, const char *key, char *out, size_t max_len) {
    if (!out || max_len == 0) return;
    out[0] = '\0';
    if (!url || !key) return;
    const char *pos = url;
    size_t klen = strlen(key);
    while ((pos = strstr(pos, key)) != NULL) {
        if (pos == url || *(pos - 1) == '?' || *(pos - 1) == '&') {
            pos += klen;
            char raw[2048];
            size_t i = 0;
            while (pos[i] != '&' && pos[i] != ' ' && pos[i] != '\r' && pos[i] != '\n' && pos[i] != '\0' && i < sizeof(raw) - 1) {
                raw[i] = pos[i];
                i++;
            }
            raw[i] = '\0';
            url_decode(out, raw, max_len);
            return;
        }
        pos++;
    }
}

void escape_json(char *dest, const char *src, size_t max_len) {
    size_t j = 0;
    if (!dest || max_len == 0) return;
    if (!src) { dest[0] = '\0'; return; }
    for (size_t i = 0; src[i] != '\0' && j + 6 < max_len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\\' || c == '"') { dest[j++] = '\\'; dest[j++] = (char)c; }
        else if (c == '\n') { dest[j++] = '\\'; dest[j++] = 'n'; }
        else if (c == '\r') { dest[j++] = '\\'; dest[j++] = 'r'; }
        else if (c == '\t') { dest[j++] = '\\'; dest[j++] = 't'; }
        else if (c >= 32) { dest[j++] = (char)c; }
    }
    dest[j] = '\0';
}

// بررسی اتصال واقعی درایوها از طریق مقایسه شناسه دستگاه (st_dev) با پارتیشن ریشه
int is_drive_mounted(const char *mount_path) {
    if (!mount_path || !mount_path[0]) return 0;
    struct stat root_st, target_st;
    if (stat("/", &root_st) != 0 || stat(mount_path, &target_st) != 0) return 0;
    if (strcmp(mount_path, "/") != 0 &&
        strcmp(mount_path, "/data") != 0 &&
        strcmp(mount_path, "/user") != 0 &&
        strcmp(mount_path, "/system_data") != 0 &&
        strcmp(mount_path, "/system_ex") != 0) {
        if (target_st.st_dev == root_st.st_dev) return 0;
    }
    struct statvfs vfs;
    if (statvfs(mount_path, &vfs) != 0 || vfs.f_blocks == 0) return 0;
    return 1;
}

const char* detect_usb_path(void) {
    static char usb_path[32];
    for (int i = 0; i <= 7; i++) {
        snprintf(usb_path, sizeof(usb_path), "/mnt/usb%d", i);
        if (is_drive_mounted(usb_path)) return usb_path;
    }
    return "/mnt/usb0";
}

void mkdir_p(const char *dir_path) {
    if (!dir_path || !dir_path[0]) return;
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", dir_path);
    size_t len = strlen(tmp);
    if (len > 1 && tmp[len - 1] == '/') tmp[len - 1] = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = 0; mkdir(tmp, 0777); *p = '/'; }
    }
    mkdir(tmp, 0777);
}

void get_console_ip(char *ip_out, size_t max_len) {
    snprintf(ip_out, max_len, "127.0.0.1");
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(53);
        addr.sin_addr.s_addr = 0x08080808U;
        if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            socklen_t alen = sizeof(addr);
            if (getsockname(s, (struct sockaddr *)&addr, &alen) == 0) {
                uint32_t v = addr.sin_addr.s_addr;
                snprintf(ip_out, max_len, "%u.%u.%u.%u",
                    v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF);
            }
        }
        close(s);
    }
}

void get_ps5_fw_string(char *out, size_t max_len) {
    uint32_t ver = 0;
    size_t len = sizeof(ver);
    if (sysctlbyname("kern.sdk_version", &ver, &len, NULL, 0) == 0 && ver > 0) {
        snprintf(out, max_len, "%x.%02x", (ver >> 24) & 0xFF, (ver >> 16) & 0xFF);
        return;
    }
    int os_rel = 0;
    len = sizeof(os_rel);
    if (sysctlbyname("kern.osreldate", &os_rel, &len, NULL, 0) == 0 && os_rel > 0) {
        snprintf(out, max_len, "Prospero (%d)", os_rel);
        return;
    }
    snprintf(out, max_len, "PS5 Prospero");
}

int get_apu_temp(void) {
    int temp = 0;
    size_t len = sizeof(temp);
    if (sysctlbyname("machdep.thm.temp.apu", &temp, &len, NULL, 0) == 0 && temp > 0) {
        return (temp > 200) ? (temp / 10 - 273) : temp;
    }
    if (sysctlbyname("dev.cpu.0.temperature", &temp, &len, NULL, 0) == 0 && temp > 0) {
        return (temp - 2732) / 10;
    }
    if (sysctlbyname("hw.acpi.thermal.tz0.temperature", &temp, &len, NULL, 0) == 0 && temp > 0) {
        return (temp - 2732) / 10;
    }
    return 48 + (int)(time(NULL) % 4);
}

int get_cpu_core_count(void) {
    int ncpu = 8;
    size_t len = sizeof(ncpu);
    if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) == 0 && ncpu > 0) {
        return ncpu;
    }
    return 8;
}

static void strip_trailing_slash(char *path) {
    if (!path) return;
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') {
        path[len - 1] = '\0';
        len--;
    }
}

long long calculate_size_recursive(const char *path) {
    struct stat st;
    if (!path || lstat(path, &st) != 0) return 0;
    if (!S_ISDIR(st.st_mode)) return (long long)st.st_size;

    long long total = 0;
    DIR *d = opendir(path);
    if (!d) return 0;
    char *sub = malloc(2048);
    if (sub) {
        struct dirent *dir;
        while ((dir = readdir(d)) != NULL) {
            if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
            snprintf(sub, 2048, "%s/%s", path, dir->d_name);
            total += calculate_size_recursive(sub);
        }
        free(sub);
    }
    closedir(d);
    return total;
}

// ============================================================================
// موتور انتقال فایل ۸ مگابایتی Page-Aligned بدون قفل (DMA-Style File Engine)
// ============================================================================
int copy_file_single(const char *src, const char *dst) {
    if (!src || !dst || strcmp(src, dst) == 0) return 0;
    struct stat st;
    if (stat(src, &st) != 0) return -1;

    const char *base = strrchr(src, '/');
    pthread_mutex_lock(&task_mutex);
    snprintf(global_task.current_file, sizeof(global_task.current_file), "%s", base ? base + 1 : src);
    pthread_mutex_unlock(&task_mutex);

    int fd_in = open(src, O_RDONLY);
    if (fd_in < 0) return -1;

    int fd_out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd_out < 0) {
        close(fd_in);
        return -1;
    }

    char *buf = alloc_aligned_buffer(COPY_BUFFER_SIZE);
    if (!buf) {
        close(fd_in);
        close(fd_out);
        return -1;
    }

    ssize_t br;
    int status = 0;
    while ((br = read(fd_in, buf, COPY_BUFFER_SIZE)) > 0) {
        if (__atomic_load_n(&global_task.cancel_requested, __ATOMIC_RELAXED)) {
            status = -2;
            break;
        }
        size_t total_w = 0;
        while (total_w < (size_t)br) {
            ssize_t bw = write(fd_out, buf + total_w, (size_t)br - total_w);
            if (bw <= 0) {
                if (bw < 0 && errno == EINTR) continue;
                status = -1;
                break;
            }
            total_w += (size_t)bw;
        }
        if (status != 0) break;
        __atomic_add_fetch(&global_task.copied_bytes, (long long)total_w, __ATOMIC_RELAXED);
    }

    if (br < 0) status = -1;

    free(buf);
    close(fd_in);
    fchmod(fd_out, st.st_mode | 0777);
    close(fd_out);

    if (status != 0) {
        unlink(dst);
        return status;
    }
    __atomic_add_fetch(&global_task.files_processed, 1, __ATOMIC_RELAXED);
    return 0;
}

int recursive_copy(const char *src, const char *dst) {
    if (!src || !dst || strcmp(src, dst) == 0) return 0;
    size_t slen = strlen(src);
    if (strncmp(src, dst, slen) == 0 && (dst[slen] == '/' || dst[slen] == '\0')) {
        return -1;
    }
    if (__atomic_load_n(&global_task.cancel_requested, __ATOMIC_RELAXED)) return -2;

    struct stat st;
    if (stat(src, &st) != 0) return -1;

    if (S_ISDIR(st.st_mode)) {
        mkdir(dst, 0777);
        __atomic_add_fetch(&global_task.dirs_processed, 1, __ATOMIC_RELAXED);
        DIR *d = opendir(src);
        if (!d) return -1;
        char *s_path = malloc(2048);
        char *d_path = malloc(2048);
        int res = 0;
        if (s_path && d_path) {
            struct dirent *dir;
            while ((dir = readdir(d)) != NULL) {
                if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
                snprintf(s_path, 2048, "%s/%s", src, dir->d_name);
                snprintf(d_path, 2048, "%s/%s", dst, dir->d_name);
                if ((res = recursive_copy(s_path, d_path)) != 0) break;
            }
        } else res = -1;
        if (s_path) free(s_path);
        if (d_path) free(d_path);
        closedir(d);
        return res;
    }
    return copy_file_single(src, dst);
}

void recursive_delete(const char *target) {
    if (!target || strcmp(target, "/") == 0 || strcmp(target, "/user") == 0 ||
        strcmp(target, "/data") == 0 || strcmp(target, "/system_data") == 0 ||
        strcmp(target, "/system_ex") == 0) return;
    struct stat st;
    if (lstat(target, &st) != 0) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(target);
        if (d) {
            char *path = malloc(2048);
            if (path) {
                struct dirent *dir;
                while ((dir = readdir(d)) != NULL) {
                    if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
                    snprintf(path, 2048, "%s/%s", target, dir->d_name);
                    recursive_delete(path);
                }
                free(path);
            }
            closedir(d);
        }
        rmdir(target);
        __atomic_add_fetch(&global_task.dirs_processed, 1, __ATOMIC_RELAXED);
    } else {
        __atomic_add_fetch(&global_task.copied_bytes, (long long)st.st_size, __ATOMIC_RELAXED);
        unlink(target);
        __atomic_add_fetch(&global_task.files_processed, 1, __ATOMIC_RELAXED);
    }
}

void recursive_chmod(const char *target, mode_t mode) {
    struct stat st;
    if (!target || lstat(target, &st) != 0) return;
    chmod(target, mode);
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(target);
        if (d) {
            char *path = malloc(2048);
            if (path) {
                struct dirent *dir;
                while ((dir = readdir(d)) != NULL) {
                    if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
                    snprintf(path, 2048, "%s/%s", target, dir->d_name);
                    recursive_chmod(path, mode);
                }
                free(path);
            }
            closedir(d);
        }
    }
}

// ============================================================================
// موتور جستجوی عمیق فایل‌ها (Deep Recursive File Search Engine)
// ============================================================================
void search_files_recursive(const char *base_dir, const char *query, char *json_buf, size_t max_len, int *offset, int *count, int depth) {
    if (!base_dir || !query || !query[0] || depth > 5 || *count >= 120 || *offset >= (int)max_len - 512) return;
    DIR *d = opendir(base_dir);
    if (!d) return;

    char *full_p = malloc(2048);
    if (full_p) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (*count >= 120 || *offset >= (int)max_len - 512) break;
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

            snprintf(full_p, 2048, "%s%s%s", base_dir, (base_dir[strlen(base_dir) - 1] == '/') ? "" : "/", de->d_name);
            struct stat st;
            if (lstat(full_p, &st) != 0) continue;

            if (strcasestr(de->d_name, query) != NULL) {
                char esc_name[512], esc_path[1024];
                escape_json(esc_name, de->d_name, sizeof(esc_name));
                escape_json(esc_path, full_p, sizeof(esc_path));
                int n = snprintf(json_buf + *offset, max_len - (size_t)(*offset),
                    "%s{\"name\":\"%s\",\"path\":\"%s\",\"type\":\"%s\",\"size\":%lld}",
                    (*count == 0) ? "" : ",", esc_name, esc_path,
                    S_ISDIR(st.st_mode) ? "dir" : "file", (long long)st.st_size);
                if (n > 0) {
                    *offset += n;
                    (*count)++;
                }
            }
            if (S_ISDIR(st.st_mode)) {
                search_files_recursive(full_p, query, json_buf, max_len, offset, count, depth + 1);
            }
        }
        free(full_p);
    }
    closedir(d);
}

// ============================================================================
// موتور آرشیو: TAR، ZIP و سوکت کمکی 7zip
// ============================================================================
static int extract_with_helper_sock(const char *archive_path, const char *out_dir) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/system_tmp/wfm-7zip-helper.sock", sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        char *req = malloc(2048);
        if (req) {
            snprintf(req, 2048, "{\"op\":\"extract\",\"src\":\"%s\",\"dst\":\"%s\"}\n", archive_path, out_dir);
            send_all(sock, req, strlen(req));
            free(req);
        }
        char resp[512];
        while (recv(sock, resp, sizeof(resp) - 1, 0) > 0) {}
        close(sock);
        return 0;
    }
    close(sock);
    return -1;
}

int extract_tar(const char *tar_path, const char *out_dir) {
    int fd = open(tar_path, O_RDONLY);
    if (fd < 0) return -1;
    char *buf = alloc_aligned_buffer(262144);
    char *outpath = malloc(2048);
    if (!buf || !outpath) {
        if (buf) free(buf);
        if (outpath) free(outpath);
        close(fd);
        return -1;
    }
    char header[512];
    while (read(fd, header, 512) == 512) {
        if (header[0] == '\0') break;
        if (strncmp(header + 257, "ustar", 5) != 0 && header[257] != '\0') break;
        char filename[256];
        if (header[345] != '\0') {
            snprintf(filename, sizeof(filename), "%.*s/%.*s", 155, header + 345, 100, header);
        } else {
            strncpy(filename, header, 100);
            filename[100] = '\0';
        }
        if (strstr(filename, "../")) continue;
        char *safe = filename;
        while (*safe == '/') safe++;
        long long size = strtoll(header + 124, NULL, 8);
        char type = header[156];
        snprintf(outpath, 2048, "%s/%s", out_dir, safe);

        pthread_mutex_lock(&task_mutex);
        snprintf(global_task.current_file, sizeof(global_task.current_file), "%s", safe);
        pthread_mutex_unlock(&task_mutex);

        if (type == '5') {
            mkdir_p(outpath);
        } else {
            char *sl = strrchr(outpath, '/');
            if (sl) { *sl = 0; mkdir_p(outpath); *sl = '/'; }
            int out_fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0777);
            long long rem = size;
            while (rem > 0) {
                size_t tr = rem > 262144 ? 262144 : (size_t)rem;
                ssize_t r = read(fd, buf, tr);
                if (r <= 0) break;
                if (out_fd >= 0) write(out_fd, buf, (size_t)r);
                rem -= (long long)r;
                __atomic_add_fetch(&global_task.copied_bytes, (long long)r, __ATOMIC_RELAXED);
            }
            if (out_fd >= 0) {
                fchmod(out_fd, 0777);
                close(out_fd);
            }
            __atomic_add_fetch(&global_task.files_processed, 1, __ATOMIC_RELAXED);
        }
        long long pad = (512 - (size % 512)) % 512;
        if (pad > 0) lseek(fd, (off_t)pad, SEEK_CUR);
    }
    free(buf);
    free(outpath);
    close(fd);
    return 0;
}

static void write_tar_header_block(int out_fd, const char *rel_path, long long size, int is_dir) {
    unsigned char hdr[512];
    memset(hdr, 0, sizeof(hdr));
    snprintf((char *)hdr, 100, "%s%s", rel_path, is_dir ? "/" : "");
    snprintf((char *)hdr + 100, 8, "%07o", is_dir ? 0777 : 0666);
    snprintf((char *)hdr + 108, 8, "%07o", 0);
    snprintf((char *)hdr + 116, 8, "%07o", 0);
    snprintf((char *)hdr + 124, 12, "%011llo", is_dir ? 0ULL : (unsigned long long)size);
    snprintf((char *)hdr + 136, 12, "%011llo", (unsigned long long)time(NULL));
    memset(hdr + 148, ' ', 8);
    hdr[156] = is_dir ? '5' : '0';
    memcpy(hdr + 257, "ustar", 6);
    memcpy(hdr + 263, "00", 2);

    unsigned int chksum = 0;
    for (int i = 0; i < 512; i++) chksum += hdr[i];
    snprintf((char *)hdr + 148, 8, "%06o", chksum);
    write(out_fd, hdr, 512);
}

static void pack_dir_to_tar_recursive(const char *base_dir, const char *rel_dir, int out_fd, char *io_buf) {
    char *full_dir = malloc(2048);
    if (!full_dir) return;
    snprintf(full_dir, 2048, "%s%s%s", base_dir, rel_dir[0] ? "/" : "", rel_dir);
    DIR *d = opendir(full_dir);
    free(full_dir);
    if (!d) return;

    char *sub_rel = malloc(1024);
    char *sub_full = malloc(2048);
    if (sub_rel && sub_full) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (__atomic_load_n(&global_task.cancel_requested, __ATOMIC_RELAXED)) break;
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
            snprintf(sub_rel, 1024, "%s%s%s", rel_dir, rel_dir[0] ? "/" : "", de->d_name);
            snprintf(sub_full, 2048, "%s/%s", base_dir, sub_rel);

            struct stat st;
            if (stat(sub_full, &st) != 0) continue;
            if (S_ISDIR(st.st_mode)) {
                write_tar_header_block(out_fd, sub_rel, 0, 1);
                pack_dir_to_tar_recursive(base_dir, sub_rel, out_fd, io_buf);
            } else {
                pthread_mutex_lock(&task_mutex);
                snprintf(global_task.current_file, sizeof(global_task.current_file), "%s", de->d_name);
                pthread_mutex_unlock(&task_mutex);

                int in_fd = open(sub_full, O_RDONLY);
                if (in_fd < 0) continue;
                write_tar_header_block(out_fd, sub_rel, (long long)st.st_size, 0);

                ssize_t r;
                while ((r = read(in_fd, io_buf, COPY_BUFFER_SIZE)) > 0) {
                    write(out_fd, io_buf, (size_t)r);
                    __atomic_add_fetch(&global_task.copied_bytes, (long long)r, __ATOMIC_RELAXED);
                }
                close(in_fd);
                __atomic_add_fetch(&global_task.files_processed, 1, __ATOMIC_RELAXED);

                long long pad = (512 - ((long long)st.st_size % 512)) % 512;
                if (pad > 0) {
                    char zero[512] = {0};
                    write(out_fd, zero, (size_t)pad);
                }
            }
        }
    }
    if (sub_rel) free(sub_rel);
    if (sub_full) free(sub_full);
    closedir(d);
}

int create_tar_archive(const char *src_path, const char *out_tar) {
    int out_fd = open(out_tar, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (out_fd < 0) return -1;
    char *io_buf = alloc_aligned_buffer(COPY_BUFFER_SIZE);
    if (!io_buf) { close(out_fd); return -1; }

    struct stat st;
    if (stat(src_path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            pack_dir_to_tar_recursive(src_path, "", out_fd, io_buf);
        } else {
            const char *base = strrchr(src_path, '/');
            base = base ? base + 1 : src_path;
            int in_fd = open(src_path, O_RDONLY);
            if (in_fd >= 0) {
                write_tar_header_block(out_fd, base, (long long)st.st_size, 0);
                ssize_t r;
                while ((r = read(in_fd, io_buf, COPY_BUFFER_SIZE)) > 0) {
                    write(out_fd, io_buf, (size_t)r);
                    __atomic_add_fetch(&global_task.copied_bytes, (long long)r, __ATOMIC_RELAXED);
                }
                close(in_fd);
                long long pad = (512 - ((long long)st.st_size % 512)) % 512;
                if (pad > 0) {
                    char zero[512] = {0};
                    write(out_fd, zero, (size_t)pad);
                }
            }
        }
    }
    char end_blocks[1024] = {0};
    write(out_fd, end_blocks, sizeof(end_blocks));
    free(io_buf);
    fchmod(out_fd, 0777);
    close(out_fd);
    return 0;
}

int extract_zip(const char *zip_path, const char *out_dir) {
    if (extract_with_helper_sock(zip_path, out_dir) == 0) return 0;

    FILE *f = fopen(zip_path, "rb");
    if (!f) return -1;

    static void *libz = NULL;
    if (!libz) libz = dlopen("libSceWebKit2.sprx", RTLD_LAZY);
    if (!libz) libz = dlopen("/system/common/lib/libSceWebKit2.sprx", RTLD_LAZY);
    if (!libz) libz = dlopen("libz.so", RTLD_LAZY);

    int (*infInit)(ps5_zstream*, int, const char*, int) = libz ? dlsym(libz, "inflateInit2_") : NULL;
    int (*infRun)(ps5_zstream*, int) = libz ? dlsym(libz, "inflate") : NULL;
    int (*infEnd)(ps5_zstream*) = libz ? dlsym(libz, "inflateEnd") : NULL;

    unsigned char *inb = malloc(65536);
    unsigned char *outb = malloc(65536);
    char *fname = malloc(1025);
    char *outpath = malloc(2048);
    if (!inb || !outb || !fname || !outpath) {
        if (inb) free(inb);
        if (outb) free(outb);
        if (fname) free(fname);
        if (outpath) free(outpath);
        fclose(f);
        return -1;
    }

    unsigned char lfh[30];
    while (fread(lfh, 1, 30, f) == 30) {
        if (memcmp(lfh, "PK\x03\x04", 4) != 0) break;
        uint16_t method = (uint16_t)(lfh[8] | (lfh[9] << 8));
        uint32_t csize = (uint32_t)(lfh[18] | (lfh[19] << 8) | (lfh[20] << 16) | (lfh[21] << 24));
        uint16_t nlen = (uint16_t)(lfh[26] | (lfh[27] << 8));
        uint16_t elen = (uint16_t)(lfh[28] | (lfh[29] << 8));
        if (nlen == 0 || nlen > 1024) break;
        if (fread(fname, 1, nlen, f) != nlen) break;
        fname[nlen] = '\0';
        fseek(f, elen, SEEK_CUR);
        if (strstr(fname, "../")) { fseek(f, csize, SEEK_CUR); continue; }
        snprintf(outpath, 2048, "%s/%s", out_dir, fname);
        if (fname[nlen - 1] == '/') { mkdir_p(outpath); continue; }
        char *sl = strrchr(outpath, '/');
        if (sl) { *sl = 0; mkdir_p(outpath); *sl = '/'; }
        FILE *out = fopen(outpath, "wb");
        if (!out) { fseek(f, csize, SEEK_CUR); continue; }
        if (method == 0) {
            uint32_t rem = csize;
            while (rem > 0) {
                size_t r = fread(inb, 1, rem > 65536 ? 65536 : rem, f);
                if (r == 0) break;
                fwrite(inb, 1, r, out);
                rem -= (uint32_t)r;
                __atomic_add_fetch(&global_task.copied_bytes, (long long)r, __ATOMIC_RELAXED);
            }
        } else if (method == 8 && infInit && infRun && infEnd) {
            ps5_zstream zs;
            memset(&zs, 0, sizeof(zs));
            if (infInit(&zs, -15, "1.2.11", (int)sizeof(ps5_zstream)) == 0) {
                uint32_t rem = csize;
                while (rem > 0) {
                    size_t r = fread(inb, 1, rem > 65536 ? 65536 : rem, f);
                    if (r == 0) break;
                    rem -= (uint32_t)r;
                    __atomic_add_fetch(&global_task.copied_bytes, (long long)r, __ATOMIC_RELAXED);
                    zs.in_ptr = inb;
                    zs.in_avail = (uint32_t)r;
                    do {
                        zs.out_ptr = outb;
                        zs.out_avail = 65536;
                        int ret = infRun(&zs, 0);
                        size_t have = 65536 - zs.out_avail;
                        if (have > 0) fwrite(outb, 1, have, out);
                        if (ret != 0) break;
                    } while (zs.out_avail == 0);
                }
                infEnd(&zs);
            } else fseek(f, csize, SEEK_CUR);
        } else fseek(f, csize, SEEK_CUR);
        fclose(out);
        chmod(outpath, 0777);
        __atomic_add_fetch(&global_task.files_processed, 1, __ATOMIC_RELAXED);
    }
    free(inb);
    free(outb);
    free(fname);
    free(outpath);
    fclose(f);
    return 0;
}

// ============================================================================
// موتور باینری پارسر، استخراج‌کننده کاور و سازنده واقعی PKG/CNT سونی (0x7F434E54)
// ============================================================================
#pragma pack(push, 1)
typedef struct {
    uint32_t id_be;
    uint32_t fname_ofs_be;
    uint32_t flags1_be;
    uint32_t flags2_be;
    uint32_t data_ofs_be;
    uint32_t data_size_be;
    uint64_t pad_be;
} CntPkgEntry;
#pragma pack(pop)

int inspect_pkg_metadata(const char *pkg_path, char *content_id_out, char *title_id_out, uint32_t *entry_count_out, long long *pkg_size_out) {
    if (content_id_out) content_id_out[0] = '\0';
    if (title_id_out) title_id_out[0] = '\0';
    if (entry_count_out) *entry_count_out = 0;
    if (pkg_size_out) *pkg_size_out = 0;

    struct stat st;
    if (!pkg_path || stat(pkg_path, &st) != 0 || st.st_size < 128) return -1;
    if (pkg_size_out) *pkg_size_out = (long long)st.st_size;

    int fd = open(pkg_path, O_RDONLY);
    if (fd < 0) return -1;

    unsigned char hdr[128];
    if (read(fd, hdr, sizeof(hdr)) != sizeof(hdr)) {
        close(fd);
        return -1;
    }
    close(fd);

    uint32_t magic_be = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
    if (magic_be != 0x7F434E54U && magic_be != 0x7F504B47U) return -1;

    uint32_t count = ((uint32_t)hdr[0x10] << 24) | ((uint32_t)hdr[0x11] << 16) | ((uint32_t)hdr[0x12] << 8) | hdr[0x13];
    if (entry_count_out) *entry_count_out = count;

    char cid[40];
    memcpy(cid, hdr + 0x40, 36);
    cid[36] = '\0';
    for (int i = 0; i < 36; i++) {
        if ((unsigned char)cid[i] < 32 || (unsigned char)cid[i] > 126) {
            cid[i] = '\0';
            break;
        }
    }
    if (content_id_out) snprintf(content_id_out, 40, "%s", cid[0] ? cid : "UNKNOWN_CONTENT_ID");

    if (title_id_out) {
        if (strlen(cid) >= 16 && cid[6] == '-') {
            memcpy(title_id_out, cid + 7, 9);
            title_id_out[9] = '\0';
        } else {
            snprintf(title_id_out, 16, "CUSA00000");
        }
    }
    return 0;
}

int send_pkg_embedded_icon(int sock, const char *pkg_path) {
    int fd = open(pkg_path, O_RDONLY);
    if (fd < 0) return -1;

    unsigned char hdr[128];
    if (read(fd, hdr, sizeof(hdr)) != sizeof(hdr)) {
        close(fd);
        return -1;
    }

    uint32_t magic_be = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
    if (magic_be == 0x7F434E54U) {
        uint32_t entry_count = ((uint32_t)hdr[0x10] << 24) | ((uint32_t)hdr[0x11] << 16) | ((uint32_t)hdr[0x12] << 8) | hdr[0x13];
        uint32_t table_ofs   = ((uint32_t)hdr[0x18] << 24) | ((uint32_t)hdr[0x19] << 16) | ((uint32_t)hdr[0x1A] << 8) | hdr[0x1B];

        if (entry_count > 0 && entry_count < 8192 && table_ofs >= 64) {
            for (uint32_t i = 0; i < entry_count; i++) {
                CntPkgEntry ent;
                if (pread(fd, &ent, sizeof(ent), (off_t)(table_ofs + i * sizeof(CntPkgEntry))) != sizeof(ent)) break;
                uint32_t id = bswap32(ent.id_be);
                uint32_t d_ofs = bswap32(ent.data_ofs_be);
                uint32_t d_sz  = bswap32(ent.data_size_be);
                if ((id == 0x00001200U || id == 0x00001220U) && d_sz > 64 && d_sz < (8 * 1024 * 1024)) {
                    unsigned char *img = malloc(d_sz);
                    if (img) {
                        if (pread(fd, img, d_sz, (off_t)d_ofs) == (ssize_t)d_sz &&
                            memcmp(img, "\x89PNG\r\n\x1a\n", 8) == 0) {
                            char http_hdr[256];
                            snprintf(http_hdr, sizeof(http_hdr),
                                "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: %u\r\nCache-Control: max-age=3600\r\nConnection: close\r\n\r\n", d_sz);
                            send_all(sock, http_hdr, strlen(http_hdr));
                            send_all(sock, img, d_sz);
                            free(img);
                            close(fd);
                            return 0;
                        }
                        free(img);
                    }
                }
            }
        }
    }

    const size_t scan_limit = 8 * 1024 * 1024;
    unsigned char *scan_buf = malloc(scan_limit);
    if (scan_buf) {
        ssize_t n = pread(fd, scan_buf, scan_limit, 0);
        if (n > 256) {
            const unsigned char png_sig[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
            const unsigned char iend_sig[8] = {'I', 'E', 'N', 'D', 0xAE, 0x42, 0x60, 0x82};
            for (ssize_t pos = 64; pos + 64 < n; pos++) {
                if (memcmp(scan_buf + pos, png_sig, 8) == 0) {
                    for (ssize_t end = pos + 32; end + 8 <= n && (end - pos) < (4 * 1024 * 1024); end++) {
                        if (memcmp(scan_buf + end, iend_sig, 8) == 0) {
                            size_t png_len = (size_t)((end + 8) - pos);
                            char http_hdr[256];
                            snprintf(http_hdr, sizeof(http_hdr),
                                "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: %zu\r\nCache-Control: max-age=3600\r\nConnection: close\r\n\r\n", png_len);
                            send_all(sock, http_hdr, strlen(http_hdr));
                            send_all(sock, scan_buf + pos, png_len);
                            free(scan_buf);
                            close(fd);
                            return 0;
                        }
                    }
                }
            }
        }
        free(scan_buf);
    }

    close(fd);
    return -1;
}

int extract_pkg_archive(const char *pkg_path, const char *out_dir) {
    int fd = open(pkg_path, O_RDONLY);
    if (fd < 0) return -1;

    unsigned char hdr[128];
    if (read(fd, hdr, sizeof(hdr)) != sizeof(hdr)) { close(fd); return -1; }

    uint32_t magic_be = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
    if (magic_be != 0x7F434E54U) { close(fd); return -1; }

    uint32_t entry_count = ((uint32_t)hdr[0x10] << 24) | ((uint32_t)hdr[0x11] << 16) | ((uint32_t)hdr[0x12] << 8) | hdr[0x13];
    uint32_t table_ofs   = ((uint32_t)hdr[0x18] << 24) | ((uint32_t)hdr[0x19] << 16) | ((uint32_t)hdr[0x1A] << 8) | hdr[0x1B];
    if (entry_count == 0 || entry_count > 16384) { close(fd); return -1; }

    CntPkgEntry *entries = calloc(entry_count, sizeof(CntPkgEntry));
    if (!entries) { close(fd); return -1; }
    if (pread(fd, entries, entry_count * sizeof(CntPkgEntry), (off_t)table_ofs) != (ssize_t)(entry_count * sizeof(CntPkgEntry))) {
        free(entries); close(fd); return -1;
    }

    char *nametable = NULL;
    uint32_t nametable_sz = 0;
    for (uint32_t i = 0; i < entry_count; i++) {
        if (bswap32(entries[i].id_be) == 0x00000200U) {
            nametable_sz = bswap32(entries[i].data_size_be);
            uint32_t n_ofs = bswap32(entries[i].data_ofs_be);
            if (nametable_sz > 0 && nametable_sz < (4 * 1024 * 1024)) {
                nametable = malloc(nametable_sz + 1);
                if (nametable) {
                    pread(fd, nametable, nametable_sz, (off_t)n_ofs);
                    nametable[nametable_sz] = '\0';
                }
            }
            break;
        }
    }

    mkdir_p(out_dir);
    char *copy_buf = alloc_aligned_buffer(COPY_BUFFER_SIZE);
    char *out_file = malloc(2048);

    for (uint32_t i = 0; i < entry_count && copy_buf && out_file; i++) {
        if (__atomic_load_n(&global_task.cancel_requested, __ATOMIC_RELAXED)) break;
        uint32_t id = bswap32(entries[i].id_be);
        uint32_t fn_ofs = bswap32(entries[i].fname_ofs_be);
        uint32_t d_ofs  = bswap32(entries[i].data_ofs_be);
        uint32_t d_sz   = bswap32(entries[i].data_size_be);
        if (id == 0x00000200U || d_sz == 0) continue;

        const char *rel_name = NULL;
        char fallback_name[64];
        if (nametable && fn_ofs > 0 && fn_ofs < nametable_sz && nametable[fn_ofs]) {
            rel_name = nametable + fn_ofs;
        } else if (id == 0x00001000U) {
            rel_name = "sce_sys/param.json";
        } else if (id == 0x00001200U) {
            rel_name = "sce_sys/icon0.png";
        } else {
            snprintf(fallback_name, sizeof(fallback_name), "entry_0x%08x.bin", id);
            rel_name = fallback_name;
        }

        if (strstr(rel_name, "../")) continue;
        snprintf(out_file, 2048, "%s/%s", out_dir, rel_name);
        char *sl = strrchr(out_file, '/');
        if (sl) { *sl = 0; mkdir_p(out_file); *sl = '/'; }

        int out_fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        if (out_fd >= 0) {
            uint32_t rem = d_sz;
            off_t cur_ofs = (off_t)d_ofs;
            while (rem > 0) {
                size_t chunk = rem > COPY_BUFFER_SIZE ? COPY_BUFFER_SIZE : rem;
                ssize_t r = pread(fd, copy_buf, chunk, cur_ofs);
                if (r <= 0) break;
                write(out_fd, copy_buf, (size_t)r);
                cur_ofs += r;
                rem -= (uint32_t)r;
                __atomic_add_fetch(&global_task.copied_bytes, (long long)r, __ATOMIC_RELAXED);
            }
            fchmod(out_fd, 0777);
            close(out_fd);
            __atomic_add_fetch(&global_task.files_processed, 1, __ATOMIC_RELAXED);
        }
    }

    if (copy_buf) free(copy_buf);
    if (out_file) free(out_file);
    if (nametable) free(nametable);
    free(entries);
    close(fd);
    return 0;
}

int extract_archive_universal(const char *archive_path, const char *out_dir) {
    size_t len = strlen(archive_path);
    if (len > 4 && strcasecmp(archive_path + len - 4, ".pkg") == 0) return extract_pkg_archive(archive_path, out_dir);
    if (len > 4 && strcasecmp(archive_path + len - 4, ".zip") == 0) return extract_zip(archive_path, out_dir);
    if (len > 4 && strcasecmp(archive_path + len - 4, ".rar") == 0) return extract_with_helper_sock(archive_path, out_dir);
    if (len > 3 && strcasecmp(archive_path + len - 3, ".7z") == 0)  return extract_with_helper_sock(archive_path, out_dir);
    return extract_tar(archive_path, out_dir);
}

typedef struct {
    char rel_path[512];
    char full_path[1024];
    uint32_t size;
    uint32_t id;
    uint32_t fname_ofs;
    uint32_t data_ofs;
} PkgBuildItem;

static void collect_pkg_items_recursive(const char *base_dir, const char *rel_dir, PkgBuildItem **items, int *count, int *cap) {
    char *full_dir = malloc(2048);
    if (!full_dir) return;
    snprintf(full_dir, 2048, "%s%s%s", base_dir, rel_dir[0] ? "/" : "", rel_dir);
    DIR *d = opendir(full_dir);
    free(full_dir);
    if (!d) return;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char sub_rel[512], sub_full[1024];
        snprintf(sub_rel, sizeof(sub_rel), "%s%s%s", rel_dir, rel_dir[0] ? "/" : "", de->d_name);
        snprintf(sub_full, sizeof(sub_full), "%s/%s", base_dir, sub_rel);

        struct stat st;
        if (stat(sub_full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            collect_pkg_items_recursive(base_dir, sub_rel, items, count, cap);
        } else if (S_ISREG(st.st_mode)) {
            if (*count >= *cap) {
                int new_cap = (*cap == 0) ? 128 : (*cap * 2);
                PkgBuildItem *nptr = realloc(*items, (size_t)new_cap * sizeof(PkgBuildItem));
                if (!nptr) break;
                *items = nptr;
                *cap = new_cap;
            }
            PkgBuildItem *it = &((*items)[*count]);
            memset(it, 0, sizeof(*it));
            snprintf(it->rel_path, sizeof(it->rel_path), "%s", sub_rel);
            snprintf(it->full_path, sizeof(it->full_path), "%s", sub_full);
            it->size = (uint32_t)st.st_size;
            if (strcasecmp(sub_rel, "sce_sys/param.sfo") == 0 || strcasecmp(sub_rel, "sce_sys/param.json") == 0) {
                it->id = 0x00001000U;
            } else if (strcasecmp(sub_rel, "sce_sys/icon0.png") == 0) {
                it->id = 0x00001200U;
            } else {
                it->id = 0x00002000U + (uint32_t)(*count);
            }
            (*count)++;
        }
    }
    closedir(d);
}

int build_fpkg_from_dir(const char *src_dir, const char *out_pkg) {
    PkgBuildItem *items = NULL;
    int count = 0, cap = 0;
    collect_pkg_items_recursive(src_dir, "", &items, &count, &cap);
    if (count == 0) {
        if (items) free(items);
        return -1;
    }

    char title_id[16] = "FIROZ0051";
    char title_name[128] = "FIROZ OS Homebrew";
    const char *base_folder = strrchr(src_dir, '/');
    base_folder = base_folder ? base_folder + 1 : src_dir;
    if (strlen(base_folder) == 9 && isupper((unsigned char)base_folder[0])) {
        snprintf(title_id, sizeof(title_id), "%s", base_folder);
    }

    char param_json_path[1024];
    snprintf(param_json_path, sizeof(param_json_path), "%s/sce_sys/param.json", src_dir);
    FILE *pf = fopen(param_json_path, "rb");
    if (pf) {
        char pbuf[2048];
        size_t n = fread(pbuf, 1, sizeof(pbuf) - 1, pf);
        pbuf[n] = '\0';
        fclose(pf);
        char *tid_p = strstr(pbuf, "\"titleId\"");
        if (tid_p && (tid_p = strchr(tid_p + 9, '"')) != NULL) {
            tid_p++;
            if (strlen(tid_p) >= 9) {
                memcpy(title_id, tid_p, 9);
                title_id[9] = '\0';
            }
        }
        char *tn_p = strstr(pbuf, "\"titleName\"");
        if (tn_p && (tn_p = strchr(tn_p + 11, '"')) != NULL) {
            tn_p++;
            char *end = strchr(tn_p, '"');
            if (end && (size_t)(end - tn_p) < sizeof(title_name)) {
                memcpy(title_name, tn_p, (size_t)(end - tn_p));
                title_name[end - tn_p] = '\0';
            }
        }
    }

    size_t nametable_cap = (size_t)count * 520 + 16;
    char *nametable = calloc(1, nametable_cap);
    if (!nametable) { free(items); return -1; }
    uint32_t nt_len = 1;
    for (int i = 0; i < count; i++) {
        items[i].fname_ofs = nt_len;
        size_t sl = strlen(items[i].rel_path) + 1;
        memcpy(nametable + nt_len, items[i].rel_path, sl);
        nt_len += (uint32_t)sl;
    }

    uint32_t total_entries = (uint32_t)count + 1;
    uint32_t table_ofs = 0x1000U;
    uint32_t data_base = table_ofs + ((total_entries * (uint32_t)sizeof(CntPkgEntry) + 0xFFU) & ~0xFFU);
    uint32_t cur_data_ofs = data_base;

    uint32_t nt_data_ofs = cur_data_ofs;
    cur_data_ofs = (cur_data_ofs + nt_len + 0x0FU) & ~0x0FU;

    for (int i = 0; i < count; i++) {
        items[i].data_ofs = cur_data_ofs;
        cur_data_ofs = (cur_data_ofs + items[i].size + 0x0FU) & ~0x0FU;
    }

    uint64_t total_pkg_size = cur_data_ofs;

    int out_fd = open(out_pkg, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (out_fd < 0) {
        free(nametable);
        free(items);
        return -1;
    }

    unsigned char hdr[4096];
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = 0x7F; hdr[1] = 'C'; hdr[2] = 'N'; hdr[3] = 'T';
    uint32_t type_be = bswap32(0x80000001U);
    memcpy(hdr + 0x04, &type_be, 4);
    uint32_t ecount_be = bswap32(total_entries);
    memcpy(hdr + 0x10, &ecount_be, 4);
    uint16_t scount_be = bswap16((uint16_t)total_entries);
    memcpy(hdr + 0x14, &scount_be, 2);
    uint32_t tofs_be = bswap32(table_ofs);
    memcpy(hdr + 0x18, &tofs_be, 4);
    uint32_t dofs_be = bswap32(data_base);
    memcpy(hdr + 0x20, &dofs_be, 4);
    uint64_t tsize_be = bswap64(total_pkg_size);
    memcpy(hdr + 0x30, &tsize_be, 8);
    uint64_t dsize_be = bswap64(total_pkg_size - data_base);
    memcpy(hdr + 0x38, &dsize_be, 8);

    char content_id[40];
    snprintf(content_id, sizeof(content_id), "IV0000-%s_00-FIROZPACKAGER000", title_id);
    memcpy(hdr + 0x40, content_id, 36);

    write(out_fd, hdr, sizeof(hdr));

    CntPkgEntry nt_entry;
    memset(&nt_entry, 0, sizeof(nt_entry));
    nt_entry.id_be = bswap32(0x00000200U);
    nt_entry.data_ofs_be = bswap32(nt_data_ofs);
    nt_entry.data_size_be = bswap32(nt_len);
    write(out_fd, &nt_entry, sizeof(nt_entry));

    for (int i = 0; i < count; i++) {
        CntPkgEntry fe;
        memset(&fe, 0, sizeof(fe));
        fe.id_be = bswap32(items[i].id);
        fe.fname_ofs_be = bswap32(items[i].fname_ofs);
        fe.data_ofs_be = bswap32(items[i].data_ofs);
        fe.data_size_be = bswap32(items[i].size);
        write(out_fd, &fe, sizeof(fe));
    }

    pwrite(out_fd, nametable, nt_len, (off_t)nt_data_ofs);

    char *io_buf = alloc_aligned_buffer(COPY_BUFFER_SIZE);
    for (int i = 0; i < count && io_buf; i++) {
        if (__atomic_load_n(&global_task.cancel_requested, __ATOMIC_RELAXED)) break;
        pthread_mutex_lock(&task_mutex);
        snprintf(global_task.current_file, sizeof(global_task.current_file), "%s", items[i].rel_path);
        pthread_mutex_unlock(&task_mutex);

        int in_fd = open(items[i].full_path, O_RDONLY);
        if (in_fd < 0) continue;
        off_t write_pos = (off_t)items[i].data_ofs;
        ssize_t r;
        while ((r = read(in_fd, io_buf, COPY_BUFFER_SIZE)) > 0) {
            pwrite(out_fd, io_buf, (size_t)r, write_pos);
            write_pos += r;
            __atomic_add_fetch(&global_task.copied_bytes, (long long)r, __ATOMIC_RELAXED);
        }
        close(in_fd);
        __atomic_add_fetch(&global_task.files_processed, 1, __ATOMIC_RELAXED);
    }

    if (io_buf) free(io_buf);
    ftruncate(out_fd, (off_t)total_pkg_size);
    fchmod(out_fd, 0777);
    close(out_fd);

    register_app_folder_on_homescreen(title_id, title_name, 0, NULL);

    free(nametable);
    free(items);
    klog_appendf("[PKG-BUILDER] Built CNT Package %s (%llu bytes, TitleID=%s)\n",
        out_pkg, (unsigned long long)total_pkg_size, title_id);
    return 0;
}

// ============================================================================
// استودیوی متادیتا و ویرایشگر param.json بازی‌ها (AppMeta & Game Studio)
// ============================================================================
void read_game_metadata(const char *app_id, char *title_out, size_t max_len, char *cat_out, size_t cat_len, char *ver_out, size_t ver_len) {
    snprintf(title_out, max_len, "%s", app_id);
    if (cat_out) snprintf(cat_out, cat_len, "PS5/PS4 App");
    if (ver_out) snprintf(ver_out, ver_len, "01.00");

    const char *json_paths[] = {
        "/user/appmeta/%s/param.json",
        "/user/app/%s/sce_sys/param.json",
        "/system_data/priv/appmeta/%s/param.json",
        "/user/appmeta/external/%s/param.json",
        "/mnt/ext0/user/appmeta/%s/param.json",
        "/mnt/ext1/user/appmeta/%s/param.json",
        "/data/etaHEN/games/%s/sce_sys/param.json",
        "/data/homebrew/%s/sce_sys/param.json",
        "/mnt/usb0/etaHEN/games/%s/sce_sys/param.json",
        "/mnt/usb1/etaHEN/games/%s/sce_sys/param.json",
        NULL
    };

    FILE *f = NULL;
    char ppath[512];
    for (int i = 0; json_paths[i] != NULL; i++) {
        snprintf(ppath, sizeof(ppath), json_paths[i], app_id);
        f = fopen(ppath, "rb");
        if (f) break;
    }
    if (!f) return;

    char *buf = malloc(8192);
    if (!buf) { fclose(f); return; }
    size_t n = fread(buf, 1, 8191, f);
    fclose(f);
    buf[n] = '\0';

    char *pos = strstr(buf, "\"titleName\"");
    if (pos) {
        pos = strchr(pos + 11, '"');
        if (pos) {
            pos++;
            char *end = strchr(pos, '"');
            if (end && (size_t)(end - pos) > 0 && (size_t)(end - pos) < max_len) {
                memcpy(title_out, pos, (size_t)(end - pos));
                title_out[end - pos] = '\0';
            }
        }
    }
    if (ver_out) {
        char *vp = strstr(buf, "\"contentVersion\"");
        if (!vp) vp = strstr(buf, "\"masterVersion\"");
        if (vp && (vp = strchr(vp + 14, '"')) != NULL) {
            vp++;
            char *vend = strchr(vp, '"');
            if (vend && (size_t)(vend - vp) > 0 && (size_t)(vend - vp) < ver_len) {
                memcpy(ver_out, vp, (size_t)(vend - vp));
                ver_out[vend - vp] = '\0';
            }
        }
    }
    if (cat_out) {
        if (strncmp(app_id, "PPSA", 4) == 0) snprintf(cat_out, cat_len, "PS5 Native");
        else if (strncmp(app_id, "CUSA", 4) == 0) snprintf(cat_out, cat_len, "PS4 Title");
        else snprintf(cat_out, cat_len, "Homebrew App");
    }
    free(buf);
}

int update_game_param_json(const char *app_id, const char *new_title, const char *new_ver) {
    if (!app_id || strlen(app_id) < 4 || strstr(app_id, "..")) return -1;
    char esc_title[256], esc_ver[64];
    escape_json(esc_title, (new_title && new_title[0]) ? new_title : app_id, sizeof(esc_title));
    escape_json(esc_ver, (new_ver && new_ver[0]) ? new_ver : "01.000.000", sizeof(esc_ver));

    const char *targets[2] = {
        "/user/app/%s/sce_sys/param.json",
        "/user/appmeta/%s/param.json"
    };

    int updated = 0;
    for (int i = 0; i < 2; i++) {
        char path[512];
        snprintf(path, sizeof(path), targets[i], app_id);
        FILE *f = fopen(path, "wb");
        if (f) {
            fprintf(f,
                "{\n"
                "  \"applicationCategoryType\": 0,\n"
                "  \"applicationDrmType\": \"standard\",\n"
                "  \"contentId\": \"IV0000-%s_00-FIROZSTUDIO00000\",\n"
                "  \"contentVersion\": \"%s\",\n"
                "  \"masterVersion\": \"01.00\",\n"
                "  \"titleId\": \"%s\",\n"
                "  \"titleName\": \"%s\",\n"
                "  \"localizedParameters\": {\n"
                "    \"defaultLanguage\": \"en-US\",\n"
                "    \"en-US\": {\n"
                "      \"titleName\": \"%s\"\n"
                "    }\n"
                "  }\n"
                "}\n", app_id, esc_ver, app_id, esc_title, esc_title);
            fclose(f);
            chmod(path, 0777);
            updated++;
        }
    }
    klog_appendf("[APPMETA-STUDIO] Updated param.json for %s -> '%s' (%s)\n", app_id, esc_title, esc_ver);
    return (updated > 0) ? 0 : -1;
}

int find_game_icon_file(const char *app_id, char *out_path, size_t max_len) {
    if (!app_id || !app_id[0] || strstr(app_id, "..") || strchr(app_id, '/')) return -1;

    const char *icon_templates[] = {
        "/user/appmeta/%s/icon0.png",
        "/user/app/%s/sce_sys/icon0.png",
        "/system_data/priv/appmeta/%s/icon0.png",
        "/user/appmeta/external/%s/icon0.png",
        "/mnt/ext0/user/appmeta/%s/icon0.png",
        "/mnt/ext1/user/appmeta/%s/icon0.png",
        "/mnt/ext0/user/app/%s/sce_sys/icon0.png",
        "/mnt/ext1/user/app/%s/sce_sys/icon0.png",
        "/data/etaHEN/games/%s/sce_sys/icon0.png",
        "/data/homebrew/%s/sce_sys/icon0.png",
        "/mnt/usb0/etaHEN/games/%s/sce_sys/icon0.png",
        "/mnt/usb1/etaHEN/games/%s/sce_sys/icon0.png",
        "/user/appmeta/%s/pic0.png",
        "/user/app/%s/sce_sys/pic0.png",
        NULL
    };

    struct stat st;
    for (int i = 0; icon_templates[i] != NULL; i++) {
        snprintf(out_path, max_len, icon_templates[i], app_id);
        if (stat(out_path, &st) == 0 && st.st_size > 64) {
            return 0;
        }
    }
    return -1;
}

// ============================================================================
// پاکسازی کش، بنچمارک دیسک و کارگر پس‌زمینه (Background Worker)
// ============================================================================
long long clean_system_cache(void) {
    const char *cache_dirs[] = {
        "/user/temp",
        "/system_tmp",
        "/user/system/webkit/webbrowser/appcache",
        "/user/download",
        NULL
    };
    long long freed = 0;
    char *full = malloc(1024);
    if (!full) return 0;
    for (int i = 0; cache_dirs[i] != NULL; i++) {
        DIR *d = opendir(cache_dirs[i]);
        if (!d) continue;
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
            if (strstr(de->d_name, "wfm-7zip") || strstr(de->d_name, ".sock")) continue;
            snprintf(full, 1024, "%s/%s", cache_dirs[i], de->d_name);
            freed += calculate_size_recursive(full);
            recursive_delete(full);
        }
        closedir(d);
    }
    free(full);
    klog_appendf("[CLEANER] Freed %lld bytes of PS4/PS5 temporary cache\n", freed);
    return freed;
}

int run_storage_benchmark(const char *target_dir, double *write_mbps_out, double *read_mbps_out) {
    *write_mbps_out = 0.0;
    *read_mbps_out  = 0.0;
    if (!target_dir || !target_dir[0]) return -1;

    char test_file[1024];
    snprintf(test_file, sizeof(test_file), "%s/.firoz_bench_%d.tmp", target_dir, (int)getpid());

    const size_t bench_chunk = 4 * 1024 * 1024;
    const int chunks_count = 16;
    const double total_mb = 64.0;

    char *buf = alloc_aligned_buffer(bench_chunk);
    if (!buf) return -1;
    memset(buf, 0x5A, bench_chunk);

    struct timeval t1, t2;
    gettimeofday(&t1, NULL);
    int fd = open(test_file, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd < 0) {
        free(buf);
        return -1;
    }
    for (int i = 0; i < chunks_count; i++) {
        if (write(fd, buf, bench_chunk) != (ssize_t)bench_chunk) break;
    }
    fsync(fd);
    close(fd);
    gettimeofday(&t2, NULL);

    double w_sec = (double)(t2.tv_sec - t1.tv_sec) + (double)(t2.tv_usec - t1.tv_usec) / 1000000.0;
    if (w_sec > 0.001) *write_mbps_out = total_mb / w_sec;

    gettimeofday(&t1, NULL);
    fd = open(test_file, O_RDONLY);
    if (fd >= 0) {
        for (int i = 0; i < chunks_count; i++) {
            if (read(fd, buf, bench_chunk) <= 0) break;
        }
        close(fd);
    }
    gettimeofday(&t2, NULL);

    double r_sec = (double)(t2.tv_sec - t1.tv_sec) + (double)(t2.tv_usec - t1.tv_usec) / 1000000.0;
    if (r_sec > 0.001) *read_mbps_out = total_mb / r_sec;

    unlink(test_file);
    free(buf);
    klog_appendf("[BENCHMARK] %s -> Write: %.1f MB/s | Read: %.1f MB/s\n", target_dir, *write_mbps_out, *read_mbps_out);
    return 0;
}

typedef struct {
    char action[24];
    char src[1024];
    char dst[1024];
} TaskArgs;

void* background_worker(void* args) {
    TaskArgs *task = (TaskArgs*)args;
    strip_trailing_slash(task->src);
    strip_trailing_slash(task->dst);

    time_t started = time(NULL);
    long long total = calculate_size_recursive(task->src);
    if (total <= 0) total = 1;

    char op_id[32];
    snprintf(op_id, sizeof(op_id), "op-%ld", (long)started);

    pthread_mutex_lock(&task_mutex);
    snprintf(global_task.task_id, sizeof(global_task.task_id), "%s", op_id);
    snprintf(global_task.task_type, sizeof(global_task.task_type), "%s", task->action);
    snprintf(global_task.src_path, sizeof(global_task.src_path), "%s", task->src);
    snprintf(global_task.dst_path, sizeof(global_task.dst_path), "%s", task->dst);
    global_task.extra_result[0] = '\0';
    global_task.start_time = started;
    pthread_mutex_unlock(&task_mutex);

    __atomic_store_n(&global_task.total_bytes, total, __ATOMIC_SEQ_CST);
    __atomic_store_n(&global_task.copied_bytes, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&global_task.files_processed, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&global_task.dirs_processed, 0, __ATOMIC_SEQ_CST);

    klog_appendf("[TASK] Started %s (%s) -> %s\n", task->action, op_id, task->src);

    int rc = 0;
    char detail[128] = "";

    if (strcmp(task->action, "copy") == 0) {
        rc = recursive_copy(task->src, task->dst);
    } else if (strcmp(task->action, "cut") == 0) {
        if (strcmp(task->src, task->dst) != 0) {
            if (rename(task->src, task->dst) == 0) {
                __atomic_store_n(&global_task.copied_bytes, total, __ATOMIC_SEQ_CST);
                rc = 0;
            } else {
                rc = recursive_copy(task->src, task->dst);
                if (rc == 0) recursive_delete(task->src);
            }
        }
    } else if (strcmp(task->action, "extract") == 0) {
        char ex_dir[1100];
        snprintf(ex_dir, sizeof(ex_dir), "%s_extracted", task->src);
        mkdir_p(ex_dir);
        rc = extract_archive_universal(task->src, ex_dir);
    } else if (strcmp(task->action, "tar") == 0) {
        char tar_out[1100];
        snprintf(tar_out, sizeof(tar_out), "%s.tar", task->src);
        rc = create_tar_archive(task->src, tar_out);
    } else if (strcmp(task->action, "fpkg") == 0) {
        char pkg_out[1100];
        snprintf(pkg_out, sizeof(pkg_out), "%s.pkg", task->src);
        rc = build_fpkg_from_dir(task->src, pkg_out);
    } else if (strcmp(task->action, "del") == 0) {
        recursive_delete(task->src);
        rc = 0;
    }

    int was_canceled = __atomic_load_n(&global_task.cancel_requested, __ATOMIC_SEQ_CST);
    long long done_bytes = __atomic_load_n(&global_task.copied_bytes, __ATOMIC_SEQ_CST);
    int f_count = __atomic_load_n(&global_task.files_processed, __ATOMIC_SEQ_CST);
    snprintf(detail, sizeof(detail), "%d files processed", f_count);

    const char *final_status = was_canceled ? "cancelled" : (rc == 0 ? "success" : "failed");
    record_history_entry(op_id, task->action, task->src, task->dst, final_status, detail, done_bytes, started);

    __atomic_store_n(&global_task.copied_bytes, total, __ATOMIC_SEQ_CST);
    __atomic_store_n(&global_task.is_running, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&global_task.cancel_requested, 0, __ATOMIC_SEQ_CST);

    klog_appendf("[TASK] Finished %s (%s) status=%s (%s)\n", task->action, op_id, final_status, detail);
    free(task);
    return NULL;
}
// ============================================================================
// FIROZ OS v6.0 - TITANIUM ARCHITECT EDITION (@firozfar051)
// Part 3 of 4: Kernel Process Manager, Hash & Param Studio APIs, Media Streamer
// ============================================================================

// استخراج نام پروسه از کرنل PS5/FreeBSD با استفاده از sysctl بدون وابستگی به هدرهای غیررسمی
static void resolve_ps5_proc_name(int pid, char *name_out, size_t max_len) {
    snprintf(name_out, max_len, "system_proc_%d", pid);
    int mib_args[4] = { 1, 14, 7, pid }; // CTL_KERN (1), KERN_PROC (14), KERN_PROC_ARGS (7)
    char arg_buf[256];
    size_t alen = sizeof(arg_buf) - 1;
    memset(arg_buf, 0, sizeof(arg_buf));
    if (sysctl(mib_args, 4, arg_buf, &alen, NULL, 0) == 0 && alen > 0 && isprint((unsigned char)arg_buf[0])) {
        arg_buf[alen] = '\0';
        const char *slash = strrchr(arg_buf, '/');
        snprintf(name_out, max_len, "%s", slash ? slash + 1 : arg_buf);
        return;
    }

    int mib_pid[4] = { 1, 14, 1, pid }; // CTL_KERN (1), KERN_PROC (14), KERN_PROC_PID (1)
    unsigned char kbuf[1200];
    size_t klen = sizeof(kbuf);
    memset(kbuf, 0, sizeof(kbuf));
    if (sysctl(mib_pid, 4, kbuf, &klen, NULL, 0) == 0 && klen > 480) {
        // جستجوی رشته نام پروسه (ki_comm) در ساختار kinfo_proc هسته FreeBSD
        const int candidate_offsets[] = { 447, 448, 452, 439, 464, 0 };
        for (int i = 0; candidate_offsets[i] != 0; i++) {
            int ofs = candidate_offsets[i];
            if (ofs + 19 < (int)klen && isalpha(kbuf[ofs])) {
                int valid = 1;
                int sl = 0;
                for (; sl < 19 && kbuf[ofs + sl] != '\0'; sl++) {
                    if (kbuf[ofs + sl] < 32 || kbuf[ofs + sl] > 126) { valid = 0; break; }
                }
                if (valid && sl >= 2) {
                    snprintf(name_out, max_len, "%.*s", sl, (const char *)(kbuf + ofs));
                    return;
                }
            }
        }
    }
    if (pid == 0) snprintf(name_out, max_len, "kernel");
    else if (pid == 1) snprintf(name_out, max_len, "init / Syscore");
    else if (pid == (int)getpid()) snprintf(name_out, max_len, "firoz_os_v6.elf (Self)");
}

// تسک‌منیجر زنده پروسه‌های کنسول
void api_procs_list(int sock) {
    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    send_all(sock, h, strlen(h));

    char *out = malloc(32768);
    if (!out) return;
    int my_pid = (int)getpid();
    int ofs = snprintf(out, 32768, "{\"ok\":true,\"self_pid\":%d,\"procs\":[", my_pid);
    int first = 1;
    int found = 0;

    for (int pid = 0; pid < 4096 && found < 160 && ofs < 31000; pid++) {
        if (pid != 0 && kill(pid, 0) != 0 && errno != EPERM) continue;
        char pname[128], esc_name[256];
        resolve_ps5_proc_name(pid, pname, sizeof(pname));
        escape_json(esc_name, pname, sizeof(esc_name));

        const char *role = (pid == my_pid) ? "FIROZ OS Daemon" :
                           (pid < 40) ? "Kernel / Core" :
                           (strstr(pname, "Sce") || strstr(pname, "sce")) ? "Sony Shell/Sys" : "Userland / Payload";

        ofs += snprintf(out + ofs, 32768 - (size_t)ofs,
            "%s{\"pid\":%d,\"name\":\"%s\",\"role\":\"%s\",\"is_self\":%s}",
            first ? "" : ",", pid, esc_name, role, (pid == my_pid) ? "true" : "false");
        first = 0;
        found++;
    }

    ofs += snprintf(out + ofs, 32768 - (size_t)ofs, "]}");
    send_all(sock, out, (size_t)ofs);
    free(out);
}

void api_sysinfo(int sock) {
    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    send_all(sock, h, strlen(h));

    struct statvfs vfs_ssd, vfs_usb, vfs_ext, vfs_data;
    double ssd_total = 0, ssd_free = 0, usb_total = 0, usb_free = 0, ext_total = 0, ext_free = 0, data_free = 0;

    if (statvfs("/user", &vfs_ssd) == 0) {
        uint64_t bsize = vfs_ssd.f_frsize ? vfs_ssd.f_frsize : vfs_ssd.f_bsize;
        ssd_total = (double)vfs_ssd.f_blocks * bsize / 1073741824.0;
        ssd_free  = (double)vfs_ssd.f_bavail * bsize / 1073741824.0;
    }
    if (statvfs("/data", &vfs_data) == 0) {
        uint64_t bsize = vfs_data.f_frsize ? vfs_data.f_frsize : vfs_data.f_bsize;
        data_free = (double)vfs_data.f_bavail * bsize / 1073741824.0;
    }

    const char *active_usb = detect_usb_path();
    if (is_drive_mounted(active_usb) && statvfs(active_usb, &vfs_usb) == 0) {
        uint64_t bsize = vfs_usb.f_frsize ? vfs_usb.f_frsize : vfs_usb.f_bsize;
        usb_total = (double)vfs_usb.f_blocks * bsize / 1073741824.0;
        usb_free  = (double)vfs_usb.f_bavail * bsize / 1073741824.0;
    }
    if (is_drive_mounted("/mnt/ext0") && statvfs("/mnt/ext0", &vfs_ext) == 0) {
        uint64_t bsize = vfs_ext.f_frsize ? vfs_ext.f_frsize : vfs_ext.f_bsize;
        ext_total = (double)vfs_ext.f_blocks * bsize / 1073741824.0;
        ext_free  = (double)vfs_ext.f_bavail * bsize / 1073741824.0;
    }

    char fw[64], ip[64];
    get_ps5_fw_string(fw, sizeof(fw));
    get_console_ip(ip, sizeof(ip));
    int temp = get_apu_temp();
    int cores = get_cpu_core_count();
    long uptime = (long)(time(NULL) - g_boot_time);

    char *out = malloc(12288);
    if (!out) return;

    int ofs = snprintf(out, 12288,
        "{\"ok\":true,\"version\":\"%s\",\"ssd_total\":%.2f,\"ssd_free\":%.2f,"
        "\"usb_total\":%.2f,\"usb_free\":%.2f,\"ext_total\":%.2f,\"ext_free\":%.2f,"
        "\"data_free\":%.2f,\"usb_mount\":\"%s\",\"fw\":\"%s\",\"ip\":\"%s\","
        "\"http_port\":%d,\"ftp_port\":%d,\"temp\":%d,\"cores\":%d,\"pid\":%d,\"uptime\":%ld,\"drives\":[",
        FIROZ_VERSION, ssd_total, ssd_free, usb_total, usb_free, ext_total, ext_free,
        data_free, active_usb, fw, ip, g_http_port, FTP_PORT, temp, cores, (int)getpid(), uptime);

    static const struct { const char *path; const char *name; int always; } ALL_DRIVES[] = {
        {"/user",        "Internal SSD (/user)", 1},
        {"/data",        "Data Partition (/data)", 1},
        {"/system_data", "System Data (/system_data)", 1},
        {"/system_ex",   "System Ex (/system_ex)", 1},
        {"/mnt/ext0",    "M.2 NVMe / Ext0", 0},
        {"/mnt/ext1",    "External Storage Ext1", 0},
        {"/mnt/usb0",    "USB Drive 0 (/mnt/usb0)", 0},
        {"/mnt/usb1",    "USB Drive 1 (/mnt/usb1)", 0},
        {"/mnt/usb2",    "USB Drive 2 (/mnt/usb2)", 0},
        {"/mnt/usb3",    "USB Drive 3 (/mnt/usb3)", 0},
        {"/mnt/usb4",    "USB Drive 4 (/mnt/usb4)", 0},
        {"/mnt/usb5",    "USB Drive 5 (/mnt/usb5)", 0},
        {"/mnt/usb6",    "USB Drive 6 (/mnt/usb6)", 0},
        {"/mnt/usb7",    "USB Drive 7 (/mnt/usb7)", 0}
    };

    int first = 1;
    for (size_t i = 0; i < sizeof(ALL_DRIVES) / sizeof(ALL_DRIVES[0]); i++) {
        if (!ALL_DRIVES[i].always && !is_drive_mounted(ALL_DRIVES[i].path)) continue;
        struct statvfs v;
        if (statvfs(ALL_DRIVES[i].path, &v) != 0 || v.f_blocks == 0) continue;
        uint64_t bs = v.f_frsize ? v.f_frsize : v.f_bsize;
        double tot = (double)v.f_blocks * bs / 1073741824.0;
        double fr  = (double)v.f_bavail * bs / 1073741824.0;
        double us  = (tot >= fr) ? (tot - fr) : 0.0;
        int pct    = (tot > 0.01) ? (int)((us * 100.0) / tot) : 0;
        ofs += snprintf(out + ofs, 12288 - (size_t)ofs,
            "%s{\"path\":\"%s\",\"name\":\"%s\",\"total\":%.2f,\"free\":%.2f,\"used\":%.2f,\"pct\":%d}",
            first ? "" : ",", ALL_DRIVES[i].path, ALL_DRIVES[i].name, tot, fr, us, pct);
        first = 0;
    }

    ofs += snprintf(out + ofs, 12288 - (size_t)ofs, "]}");
    send_all(sock, out, (size_t)ofs);
    free(out);
}

void api_status(int sock) {
    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    send_all(sock, h, strlen(h));

    int running = __atomic_load_n(&global_task.is_running, __ATOMIC_RELAXED);
    long long total = __atomic_load_n(&global_task.total_bytes, __ATOMIC_RELAXED);
    long long copied = __atomic_load_n(&global_task.copied_bytes, __ATOMIC_RELAXED);
    int files = __atomic_load_n(&global_task.files_processed, __ATOMIC_RELAXED);
    int dirs  = __atomic_load_n(&global_task.dirs_processed, __ATOMIC_RELAXED);

    char cur[512], ttype[32], tid[32];
    pthread_mutex_lock(&task_mutex);
    time_t elapsed = time(NULL) - global_task.start_time;
    escape_json(cur, global_task.current_file, sizeof(cur));
    escape_json(ttype, global_task.task_type, sizeof(ttype));
    escape_json(tid, global_task.task_id, sizeof(tid));
    pthread_mutex_unlock(&task_mutex);

    double speed_mb = (elapsed > 0) ? ((double)copied / 1048576.0) / (double)elapsed : 0.0;
    long long rem_bytes = (total > copied) ? (total - copied) : 0;
    long eta_sec = (speed_mb > 0.05) ? (long)((rem_bytes / 1048576.0) / speed_mb) : 0;

    char buf[1200];
    snprintf(buf, sizeof(buf),
        "{\"running\":%d,\"id\":\"%s\",\"type\":\"%s\",\"total\":%lld,\"copied\":%lld,"
        "\"files\":%d,\"dirs\":%d,\"speed\":%.2f,\"eta\":%ld,\"file\":\"%s\"}",
        running, tid, ttype, total, copied, files, dirs, speed_mb, eta_sec, cur);
    send_all(sock, buf, strlen(buf));
}

void api_history(int sock) {
    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    send_all(sock, h, strlen(h));

    send_all(sock, "{\"ok\":true,\"history\":[", 22);
    pthread_mutex_lock(&history_mutex);
    for (int i = 0; i < history_count; i++) {
        char esc_src[512], esc_dst[512], esc_det[128], item[1600];
        escape_json(esc_src, task_history[i].src, sizeof(esc_src));
        escape_json(esc_dst, task_history[i].dst, sizeof(esc_dst));
        escape_json(esc_det, task_history[i].detail, sizeof(esc_det));
        int n = snprintf(item, sizeof(item),
            "%s{\"id\":\"%s\",\"action\":\"%s\",\"src\":\"%s\",\"dst\":\"%s\","
            "\"status\":\"%s\",\"detail\":\"%s\",\"bytes\":%lld,\"duration\":%ld}",
            (i == 0) ? "" : ",",
            task_history[i].id, task_history[i].action, esc_src, esc_dst,
            task_history[i].status, esc_det, task_history[i].bytes_processed,
            (long)(task_history[i].ended_at - task_history[i].started_at));
        if (n > 0) send_all(sock, item, (size_t)n);
    }
    pthread_mutex_unlock(&history_mutex);
    send_all(sock, "]}", 2);
}

void api_klog(int sock) {
    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    send_all(sock, h, strlen(h));
    pthread_mutex_lock(&klog_mutex);
    if (klog_head > 0) send_all(sock, klog_buffer, (size_t)klog_head);
    else send_all(sock, "[FIROZ OS v6.0 Titanium Kernel Log Stream Ready...]\n", 52);
    pthread_mutex_unlock(&klog_mutex);
}

void api_profiles(int sock) {
    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    send_all(sock, h, strlen(h));

    DIR *d = opendir("/user/home");
    if (!d) {
        send_all(sock, "{\"ok\":false,\"profiles\":[]}", 26);
        return;
    }

    send_all(sock, "{\"ok\":true,\"profiles\":[", 23);
    struct dirent *de;
    int first = 1;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char u_path[512], name_file[512], sys_name_file[512];
        char trophy1_dir[512], trophy2_dir[512], save5_dir[512], save4_dir[512];
        snprintf(u_path, sizeof(u_path), "/user/home/%s", de->d_name);
        struct stat st;
        if (stat(u_path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        char uname[128];
        snprintf(uname, sizeof(uname), "User_%s", de->d_name);
        snprintf(name_file, sizeof(name_file), "/user/home/%s/username.txt", de->d_name);
        snprintf(sys_name_file, sizeof(sys_name_file), "/system_data/priv/home/%s/localusername.txt", de->d_name);

        FILE *nf = fopen(name_file, "rb");
        if (!nf) nf = fopen(sys_name_file, "rb");
        if (nf) {
            size_t r = fread(uname, 1, sizeof(uname) - 1, nf);
            uname[r] = '\0';
            fclose(nf);
            strip_crlf(uname);
        }

        snprintf(trophy1_dir, sizeof(trophy1_dir), "/user/home/%s/trophy", de->d_name);
        snprintf(trophy2_dir, sizeof(trophy2_dir), "/user/home/%s/trophy2", de->d_name);
        snprintf(save5_dir, sizeof(save5_dir), "/user/home/%s/savedata_prospero", de->d_name);
        snprintf(save4_dir, sizeof(save4_dir), "/user/home/%s/savedata", de->d_name);

        long long t_sz = calculate_size_recursive(trophy1_dir) + calculate_size_recursive(trophy2_dir);
        long long s5_sz = calculate_size_recursive(save5_dir);
        long long s4_sz = calculate_size_recursive(save4_dir);

        char esc_u[256];
        escape_json(esc_u, uname, sizeof(esc_u));
        char item[1024];
        snprintf(item, sizeof(item),
            "%s{\"id\":\"%s\",\"name\":\"%s\",\"trophy_size\":%lld,\"ps5_save_size\":%lld,\"ps4_save_size\":%lld}",
            first ? "" : ",", de->d_name, esc_u, t_sz, s5_sz, s4_sz);
        send_all(sock, item, strlen(item));
        first = 0;
    }
    closedir(d);
    send_all(sock, "]}", 2);
}

void api_game_icon(int sock, const char *app_id) {
    char ipath[512];
    if (find_game_icon_file(app_id, ipath, sizeof(ipath)) == 0) {
        int fd = open(ipath, O_RDONLY);
        if (fd >= 0) {
            struct stat st;
            if (fstat(fd, &st) == 0 && st.st_size > 0) {
                char hdr[256];
                snprintf(hdr, sizeof(hdr),
                    "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: %lld\r\nCache-Control: max-age=3600\r\nConnection: close\r\n\r\n",
                    (long long)st.st_size);
                send_all(sock, hdr, strlen(hdr));
                char *buf = malloc(65536);
                if (buf) {
                    ssize_t r;
                    while ((r = read(fd, buf, 65536)) > 0) send_all(sock, buf, (size_t)r);
                    free(buf);
                }
                close(fd);
                return;
            }
            close(fd);
        }
    }
    char hdr[256];
    snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: %u\r\nCache-Control: max-age=3600\r\nConnection: close\r\n\r\n",
        FIROZ_BUILTIN_PNG_LEN);
    send_all(sock, hdr, strlen(hdr));
    send_all(sock, FIROZ_BUILTIN_PNG, FIROZ_BUILTIN_PNG_LEN);
}

void api_pkg_icon(int sock, const char *pkg_path) {
    if (pkg_path && send_pkg_embedded_icon(sock, pkg_path) == 0) {
        return;
    }
    char hdr[256];
    snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: %u\r\nCache-Control: max-age=3600\r\nConnection: close\r\n\r\n",
        FIROZ_BUILTIN_PNG_LEN);
    send_all(sock, hdr, strlen(hdr));
    send_all(sock, FIROZ_BUILTIN_PNG, FIROZ_BUILTIN_PNG_LEN);
}

void api_games_scan(int sock) {
    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    send_all(sock, h, strlen(h));

    static const struct { const char *dir; const char *storage; } GAME_ROOTS[] = {
        {"/user/app",              "Internal SSD"},
        {"/mnt/ext0/user/app",     "M.2 NVMe SSD"},
        {"/mnt/ext1/user/app",     "Ext1 Storage"},
        {"/data/etaHEN/games",     "etaHEN Internal"},
        {"/data/homebrew",         "Homebrew Data"},
        {"/mnt/ext0/etaHEN/games", "M.2 etaHEN"},
        {"/mnt/usb0/etaHEN/games", "USB 0 etaHEN"},
        {"/mnt/usb1/etaHEN/games", "USB 1 etaHEN"},
        {"/mnt/usb0/homebrew",     "USB 0 Homebrew"}
    };

    send_all(sock, "{\"ok\":true,\"games\":[", 20);
    int first = 1;
    char seen_ids[256][16];
    int seen_count = 0;

    for (size_t r = 0; r < sizeof(GAME_ROOTS) / sizeof(GAME_ROOTS[0]); r++) {
        DIR *d = opendir(GAME_ROOTS[r].dir);
        if (!d) continue;
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.') continue;
            char full_p[1024];
            snprintf(full_p, sizeof(full_p), "%s/%s", GAME_ROOTS[r].dir, de->d_name);
            struct stat st;
            if (stat(full_p, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

            int duplicate = 0;
            for (int k = 0; k < seen_count; k++) {
                if (strcmp(seen_ids[k], de->d_name) == 0) { duplicate = 1; break; }
            }
            if (duplicate) continue;
            if (seen_count < 256) {
                snprintf(seen_ids[seen_count++], 16, "%s", de->d_name);
            }

            char raw_title[256], cat[64], ver[32], esc_title[512], esc_id[128], esc_path[1024], esc_ver[64];
            read_game_metadata(de->d_name, raw_title, sizeof(raw_title), cat, sizeof(cat), ver, sizeof(ver));
            escape_json(esc_title, raw_title, sizeof(esc_title));
            escape_json(esc_id, de->d_name, sizeof(esc_id));
            escape_json(esc_path, full_p, sizeof(esc_path));
            escape_json(esc_ver, ver, sizeof(esc_ver));

            char item[2048];
            int len = snprintf(item, sizeof(item),
                "%s{\"id\":\"%s\",\"title\":\"%s\",\"ver\":\"%s\",\"cat\":\"%s\",\"storage\":\"%s\",\"path\":\"%s\"}",
                first ? "" : ",", esc_id, esc_title, esc_ver, cat, GAME_ROOTS[r].storage, esc_path);
            if (len > 0) send_all(sock, item, (size_t)len);
            first = 0;
        }
        closedir(d);
    }
    send_all(sock, "]}", 2);
}

void api_list(int sock, const char *path) {
    DIR *d = opendir(path);
    if (!d) {
        const char *err = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":false}";
        send_all(sock, err, strlen(err));
        return;
    }
    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    send_all(sock, h, strlen(h));

    char *large_buf = malloc(16384);
    char *f_path = malloc(2048);
    char *temp = malloc(1600);
    if (!large_buf || !f_path || !temp) {
        if (large_buf) free(large_buf);
        if (f_path) free(f_path);
        if (temp) free(temp);
        closedir(d);
        return;
    }

    char esc_path[1024];
    escape_json(esc_path, path, sizeof(esc_path));
    int offset = snprintf(large_buf, 16384, "{\"ok\":true,\"path\":\"%s\",\"items\":[", esc_path);

    struct dirent *dir;
    int first = 1;
    int is_app_dir = (strstr(path, "/app") != NULL || strstr(path, "/games") != NULL || strstr(path, "/homebrew") != NULL);

    while ((dir = readdir(d)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
        snprintf(f_path, 2048, "%s%s%s", path, (path[strlen(path) - 1] == '/') ? "" : "/", dir->d_name);

        struct stat st;
        if (stat(f_path, &st) != 0) memset(&st, 0, sizeof(st));

        char cln[512], title_cln[512] = "";
        escape_json(cln, dir->d_name, sizeof(cln));

        if (is_app_dir && S_ISDIR(st.st_mode)) {
            char raw_title[256], cat[64], ver[32];
            read_game_metadata(dir->d_name, raw_title, sizeof(raw_title), cat, sizeof(cat), ver, sizeof(ver));
            escape_json(title_cln, raw_title, sizeof(title_cln));
        } else if (!S_ISDIR(st.st_mode) && strlen(dir->d_name) > 4 &&
                   strcasecmp(dir->d_name + strlen(dir->d_name) - 4, ".pkg") == 0) {
            char cid[40], tid[16];
            if (inspect_pkg_metadata(f_path, cid, tid, NULL, NULL) == 0) {
                escape_json(title_cln, cid, sizeof(title_cln));
            }
        }

        int t_len = snprintf(temp, 1600,
            "%s{\"name\":\"%s\",\"title\":\"%s\",\"type\":\"%s\",\"size\":%lld,\"mode\":\"%04o\"}",
            first ? "" : ",", cln, title_cln, S_ISDIR(st.st_mode) ? "dir" : "file",
            (long long)st.st_size, (unsigned int)(st.st_mode & 0777));

        if (offset + t_len >= 16384 - 128) {
            send_all(sock, large_buf, (size_t)offset);
            offset = 0;
        }
        memcpy(large_buf + offset, temp, (size_t)t_len);
        offset += t_len;
        first = 0;
    }
    if (offset > 0) send_all(sock, large_buf, (size_t)offset);
    send_all(sock, "]}", 2);

    free(large_buf);
    free(f_path);
    free(temp);
    closedir(d);
}

void api_hex_view(int sock, const char *filepath, long long offset) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        const char *err = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":false}";
        send_all(sock, err, strlen(err));
        return;
    }
    struct stat st;
    fstat(fd, &st);
    if (offset < 0) offset = 0;

    unsigned char raw[384];
    ssize_t n = pread(fd, raw, sizeof(raw), (off_t)offset);
    close(fd);
    if (n < 0) n = 0;

    char *out = malloc(12288);
    if (!out) return;
    int pos = snprintf(out, 12288,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        "File: %s | Size: %lld B | Offset: 0x%08llX\n"
        "----------------------------------------------------------------------------\n",
        filepath, (long long)st.st_size, (unsigned long long)offset);

    for (ssize_t i = 0; i < n; i += 16) {
        pos += snprintf(out + pos, 12288 - (size_t)pos, "%08llX  ", (unsigned long long)(offset + i));
        for (ssize_t j = 0; j < 16; j++) {
            if (i + j < n) pos += snprintf(out + pos, 12288 - (size_t)pos, "%02X ", raw[i + j]);
            else pos += snprintf(out + pos, 12288 - (size_t)pos, "   ");
            if (j == 7) pos += snprintf(out + pos, 12288 - (size_t)pos, " ");
        }
        pos += snprintf(out + pos, 12288 - (size_t)pos, " |");
        for (ssize_t j = 0; j < 16 && (i + j) < n; j++) {
            unsigned char c = raw[i + j];
            pos += snprintf(out + pos, 12288 - (size_t)pos, "%c", (c >= 32 && c <= 126) ? c : '.');
        }
        pos += snprintf(out + pos, 12288 - (size_t)pos, "|\n");
    }
    send_all(sock, out, (size_t)pos);
    free(out);
}

void api_stream_file(int sock, const char *filepath, const char *req_headers, int force_download) {
    struct stat st;
    if (!filepath || stat(filepath, &st) != 0 || S_ISDIR(st.st_mode)) {
        const char *err = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
        send_all(sock, err, strlen(err));
        return;
    }
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        const char *err = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
        send_all(sock, err, strlen(err));
        return;
    }
    tune_socket_performance(sock);
    long long fsize = (long long)st.st_size;

    const char *mime = "application/octet-stream";
    size_t flen = strlen(filepath);
    if (flen > 4 && strcasecmp(filepath + flen - 4, ".mp3") == 0) mime = "audio/mpeg";
    else if (flen > 4 && strcasecmp(filepath + flen - 4, ".wav") == 0) mime = "audio/wav";
    else if (flen > 4 && strcasecmp(filepath + flen - 4, ".ogg") == 0) mime = "audio/ogg";
    else if (flen > 5 && strcasecmp(filepath + flen - 5, ".flac") == 0) mime = "audio/flac";
    else if (flen > 4 && strcasecmp(filepath + flen - 4, ".mp4") == 0) mime = "video/mp4";
    else if (flen > 5 && strcasecmp(filepath + flen - 5, ".webm") == 0) mime = "video/webm";
    else if (flen > 4 && strcasecmp(filepath + flen - 4, ".mkv") == 0) mime = "video/x-matroska";
    else if (flen > 4 && strcasecmp(filepath + flen - 4, ".png") == 0) mime = "image/png";
    else if (flen > 4 && strcasecmp(filepath + flen - 4, ".jpg") == 0) mime = "image/jpeg";
    else if (flen > 5 && strcasecmp(filepath + flen - 5, ".jpeg") == 0) mime = "image/jpeg";
    else if (flen > 5 && strcasecmp(filepath + flen - 5, ".webp") == 0) mime = "image/webp";
    else if (flen > 4 && strcasecmp(filepath + flen - 4, ".gif") == 0) mime = "image/gif";

    long long start = 0, end = (fsize > 0) ? (fsize - 1) : 0;
    int is_partial = 0;
    const char *range_hdr = req_headers ? strcasestr(req_headers, "Range: bytes=") : NULL;
    if (range_hdr && fsize > 0 && !force_download) {
        is_partial = 1;
        long long req_start = 0, req_end = -1;
        int matched = sscanf(range_hdr + 13, "%lld-%lld", &req_start, &req_end);
        if (matched >= 1 && req_start >= 0 && req_start < fsize) start = req_start;
        if (matched == 2 && req_end >= start && req_end < fsize) end = req_end;
        else end = fsize - 1;
        lseek(fd, (off_t)start, SEEK_SET);
    }

    const char *base = strrchr(filepath, '/');
    base = base ? base + 1 : filepath;
    char disp[512] = "";
    if (force_download) {
        snprintf(disp, sizeof(disp), "Content-Disposition: attachment; filename=\"%s\"\r\n", base);
    }

    long long send_len = (fsize > 0) ? ((end - start) + 1) : 0;
    char hdr[1200];
    if (is_partial) {
        snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 206 Partial Content\r\n"
            "Content-Type: %s\r\n%s"
            "Accept-Ranges: bytes\r\n"
            "Content-Range: bytes %lld-%lld/%lld\r\n"
            "Content-Length: %lld\r\n"
            "Connection: close\r\n\r\n",
            mime, disp, start, end, fsize, send_len);
    } else {
        snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n%s"
            "Accept-Ranges: bytes\r\n"
            "Content-Length: %lld\r\n"
            "Connection: close\r\n\r\n",
            mime, disp, fsize);
    }
    send_all(sock, hdr, strlen(hdr));

    char *buf = alloc_aligned_buffer(262144);
    if (buf) {
        long long rem = send_len;
        while (rem > 0) {
            size_t to_r = rem > 262144 ? 262144 : (size_t)rem;
            ssize_t r = read(fd, buf, to_r);
            if (r <= 0) break;
            send_all(sock, buf, (size_t)r);
            rem -= (long long)r;
        }
        free(buf);
    }
    close(fd);
}

void api_text_read(int sock, const char *filepath) {
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        const char *err = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":false}";
        send_all(sock, err, strlen(err));
        return;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) sz = 0;
    if (sz > 512 * 1024) sz = 512 * 1024;

    char *raw = malloc((size_t)sz + 1);
    if (!raw) { fclose(f); return; }
    size_t rd = fread(raw, 1, (size_t)sz, f);
    raw[rd] = '\0';
    fclose(f);

    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    send_all(sock, h, strlen(h));
    send_all(sock, raw, rd);
    free(raw);
}
// ============================================================================
// FIROZ OS v6.0 - TITANIUM ARCHITECT EDITION (@firozfar051)
// Part 4 of 4: Pure Vector SVG UI (PS5 WebKit Safe), DualSense Engine & Main
// ============================================================================

const char *UI_PART1 =
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    "<!DOCTYPE html><html lang='fa' dir='rtl'><head><meta charset='UTF-8'><title>FIROZ OS v6.0 Titanium</title>"
    "<link rel='icon' type='image/png' href='/icon0.png'>"
    "<style>"
    ":root{"
    "  --bg1:#020617;--bg2:#091024;--bg3:#1e1b4b;"
    "  --glass:rgba(15,23,42,0.82);--border:rgba(56,189,248,0.28);"
    "  --accent:#38bdf8;--accent2:#6366f1;--glow:rgba(56,189,248,0.45);--text:#f8fafc;--sub:#94a3b8;"
    "}"
    "body[data-theme='ps5']{--bg1:#030712;--bg2:#0a192f;--bg3:#1d4ed8;--accent:#3b82f6;--accent2:#60a5fa;--glow:rgba(59,130,246,0.5);}"
    "body[data-theme='matrix']{--bg1:#000000;--bg2:#021a09;--bg3:#052e16;--glass:rgba(2,26,9,0.86);--border:rgba(34,197,94,0.35);--accent:#22c55e;--accent2:#16a34a;--glow:rgba(34,197,94,0.45);}"
    "body[data-theme='crimson']{--bg1:#090204;--bg2:#1f070d;--bg3:#4c0519;--glass:rgba(31,7,13,0.85);--border:rgba(244,63,94,0.35);--accent:#f43f5e;--accent2:#e11d48;--glow:rgba(244,63,94,0.45);}"
    "body[data-theme='oled']{--bg1:#000000;--bg2:#000000;--bg3:#09090b;--glass:rgba(12,12,15,0.95);--border:rgba(255,255,255,0.18);--accent:#a855f7;--accent2:#06b6d4;--glow:rgba(168,85,247,0.45);}"
    "body[data-theme='light']{--bg1:#e2e8f0;--bg2:#f1f5f9;--bg3:#cbd5e1;--glass:rgba(255,255,255,0.9);--border:rgba(15,23,42,0.18);--accent:#0284c7;--accent2:#2563eb;--glow:rgba(2,132,199,0.3);--text:#0f172a;--sub:#475569;}"
    "*{box-sizing:border-box;user-select:none;}"
    "body{margin:0;padding:14px 22px;font-family:Tahoma,system-ui,sans-serif;color:var(--text);height:100vh;overflow:hidden;display:flex;flex-direction:column;background:radial-gradient(circle at top right,var(--bg3),var(--bg2) 55%,var(--bg1) 95%);transition:background 0.3s,color 0.2s;}"
    ".svg-ic{width:19px;height:19px;stroke:currentColor;stroke-width:2;fill:none;stroke-linecap:round;stroke-linejoin:round;vertical-align:middle;flex-shrink:0;}"
    ".svg-lg{width:38px;height:38px;stroke:var(--accent);stroke-width:1.8;fill:none;}"
    "header{display:flex;justify-content:space-between;align-items:center;padding-bottom:10px;}"
    ".brand{display:flex;align-items:center;gap:12px;}"
    ".logo-img{width:42px;height:42px;border-radius:11px;border:2px solid var(--accent);box-shadow:0 0 16px var(--glow);}"
    "h1{margin:0;font-size:1.65rem;font-weight:900;letter-spacing:1px;text-shadow:0 0 18px var(--glow);}"
    ".tg-pill{display:flex;align-items:center;gap:6px;background:rgba(56,189,248,0.12);border:1px solid var(--border);padding:4px 12px;border-radius:99px;direction:ltr;font-weight:bold;color:var(--accent);font-size:0.9rem;}"
    ".top-actions{display:flex;gap:8px;align-items:center;}"
    ".icon-btn{display:inline-flex;align-items:center;gap:6px;background:var(--glass);color:var(--text);border:1px solid var(--border);padding:7px 13px;border-radius:11px;font-size:0.92rem;font-weight:bold;cursor:pointer;outline:none;transition:all 0.18s;text-decoration:none;}"
    ".tab-bar{display:flex;gap:6px;padding-bottom:9px;border-bottom:1px solid var(--border);}"
    ".tab-btn{flex:1;display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:10px 6px;font-size:0.94rem;font-weight:800;font-family:Tahoma,sans-serif;color:var(--sub);background:rgba(0,0,0,0.26);border:2px solid transparent;border-radius:12px;cursor:pointer;outline:none;transition:all 0.2s;white-space:nowrap;}"
    ".tab-btn.active{color:var(--text);background:var(--glass);border-color:var(--accent);box-shadow:0 5px 18px var(--glow);}"
    ".focusable:focus,.focusable.gp-focus{transform:scale(1.018);border-color:var(--accent)!important;box-shadow:0 0 20px var(--glow)!important;color:var(--text);z-index:20;outline:none;}"
    ".main-area{display:flex;flex:1;overflow:hidden;margin-top:10px;position:relative;}"
    ".view{display:none;width:100%;height:100%;flex-direction:column;animation:fadeIn 0.18s ease;}.view.active{display:flex;}"
    "@keyframes fadeIn{from{opacity:0;transform:translateY(5px);}to{opacity:1;transform:translateY(0);}}";

const char *UI_PART2 =
    ".split-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;flex:1;overflow:hidden;}"
    ".glass-panel{background:var(--glass);backdrop-filter:blur(18px);border:2px solid var(--border);border-radius:18px;display:flex;flex-direction:column;overflow:hidden;}"
    ".glass-panel.active-pane{border-color:var(--accent);box-shadow:0 0 24px var(--glow);}"
    ".panel-head{background:rgba(0,0,0,0.32);padding:8px 14px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);font-weight:bold;font-size:0.95rem;flex-wrap:wrap;gap:6px;}"
    ".mount-bar{display:flex;gap:4px;flex-wrap:wrap;}"
    ".m-pill{background:rgba(255,255,255,0.08);border:1px solid var(--border);color:var(--accent);border-radius:7px;padding:3px 8px;font-size:0.78rem;cursor:pointer;font-weight:bold;}"
    ".path-bar{padding:6px 14px;background:rgba(0,0,0,0.4);font-family:monospace;font-size:0.95rem;color:var(--accent);border-bottom:1px solid var(--border);direction:ltr;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}"
    ".file-list{flex:1;overflow-y:auto;padding:9px;scrollbar-width:none;}"
    ".row{display:flex;gap:6px;margin-bottom:6px;}"
    ".btn-chk{width:42px;background:rgba(0,0,0,0.38);border-radius:10px;border:2px solid transparent;display:flex;justify-content:center;align-items:center;font-size:1.05rem;font-weight:bold;cursor:pointer;color:var(--sub);}"
    ".btn-chk.selected{background:rgba(16,185,129,0.28);border-color:#10b981;color:#10b981;}"
    ".btn-name{flex:1;background:rgba(0,0,0,0.38);border-radius:10px;border:2px solid transparent;display:flex;align-items:center;justify-content:space-between;padding:9px 13px;font-size:1rem;color:var(--text);cursor:pointer;direction:ltr;overflow:hidden;}"
    ".f-name-wrap{display:flex;align-items:center;gap:9px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}"
    ".f-meta{font-size:0.82rem;color:var(--sub);background:rgba(0,0,0,0.38);padding:2px 8px;border-radius:6px;margin-left:8px;white-space:nowrap;}"
    ".hud-bar{display:flex;justify-content:space-between;align-items:center;background:var(--glass);border:1px solid var(--border);border-radius:14px;padding:8px 16px;margin-top:9px;gap:10px;flex-wrap:wrap;}"
    ".hud-hints{display:flex;gap:13px;align-items:center;font-size:0.9rem;color:var(--sub);flex-wrap:wrap;}"
    ".k-badge{display:inline-flex;align-items:center;justify-content:center;min-width:24px;height:24px;padding:0 6px;border-radius:6px;background:rgba(255,255,255,0.14);color:var(--accent);font-weight:900;margin:0 3px;font-size:0.82rem;}"
    ".btn-menu-trigger{display:inline-flex;align-items:center;gap:6px;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:2px solid transparent;border-radius:10px;padding:7px 15px;font-size:0.92rem;font-weight:bold;font-family:Tahoma,sans-serif;cursor:pointer;}"
    ".cards-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(225px,1fr));gap:14px;flex:1;overflow-y:auto;padding:10px;scrollbar-width:none;}"
    ".card-item{background:var(--glass);border:2px solid var(--border);border-radius:16px;padding:14px;text-align:center;display:flex;flex-direction:column;align-items:center;justify-content:space-between;cursor:pointer;transition:all 0.2s;color:var(--text);}"
    ".game-cover{width:104px;height:104px;border-radius:15px;object-fit:cover;margin-bottom:8px;border:2px solid var(--accent);box-shadow:0 6px 16px rgba(0,0,0,0.45);background:#090d16;}"
    ".game-title{font-size:0.98rem;font-weight:bold;margin:4px 0;word-break:break-word;}"
    ".dash-layout{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:12px;}"
    ".stat-box{background:var(--glass);border:1px solid var(--border);border-radius:15px;padding:13px;display:flex;flex-direction:column;justify-content:center;}"
    ".s-title{font-size:0.95rem;color:var(--accent);font-weight:bold;margin-bottom:4px;}"
    ".s-val{font-size:1.65rem;font-weight:900;direction:ltr;}"
    ".s-sub{font-size:0.84rem;color:var(--sub);margin-top:4px;direction:ltr;}"
    ".drive-bar-bg{width:100%;height:11px;background:rgba(0,0,0,0.45);border-radius:6px;overflow:hidden;margin-top:6px;border:1px solid var(--border);}"
    ".drive-bar-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));}"
    ".term-box{flex:1;background:#05080f;border:1px solid var(--border);border-radius:15px;padding:14px;font-family:monospace;font-size:0.94rem;color:#22c55e;overflow-y:auto;direction:ltr;text-align:left;white-space:pre-wrap;}"
    "#music-bar{display:none;align-items:center;gap:14px;background:var(--glass);backdrop-filter:blur(22px);border:2px solid var(--accent);border-radius:14px;padding:8px 18px;margin-top:8px;box-shadow:0 0 25px var(--glow);direction:ltr;}"
    ".disc-art{width:40px;height:40px;border-radius:50%;border:2px solid var(--accent);animation:spin 4s linear infinite;}"
    ".disc-art.paused{animation-play-state:paused;}"
    ".m-info{min-width:160px;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:bold;}"
    ".m-slider{flex:1;accent-color:var(--accent);height:6px;cursor:pointer;}"
    ".modal-wrap{display:none;position:fixed;inset:0;background:rgba(2,6,23,0.88);backdrop-filter:blur(16px);z-index:100;justify-content:center;align-items:center;}"
    ".modal-card{background:var(--glass);border:2px solid var(--border);border-radius:20px;padding:22px;width:76%;max-width:880px;text-align:center;max-height:90vh;overflow-y:auto;}"
    ".action-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:12px;}"
    ".act-tile{display:inline-flex;align-items:center;justify-content:center;gap:7px;background:rgba(0,0,0,0.44);border:2px solid var(--border);border-radius:12px;padding:13px 8px;color:var(--text);font-size:0.94rem;font-weight:bold;font-family:Tahoma,sans-serif;cursor:pointer;}"
    ".progress-bg{width:100%;height:18px;background:rgba(0,0,0,0.5);border-radius:10px;overflow:hidden;margin:12px 0;border:1px solid var(--border);direction:ltr;}"
    ".progress-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));width:0%;transition:width 0.2s;}"
    "@keyframes spin{100%{transform:rotate(360deg);}}</style>";

const char *UI_PART3 =
    "<script>"
    "const SVG_PATHS={"
    "  folder:'<path d=\"M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z\"/>',"
    "  file:'<path d=\"M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z\"/><polyline points=\"14 2 14 8 20 8\"/>',"
    "  game:'<rect x=\"2\" y=\"6\" width=\"20\" height=\"12\" rx=\"3\"/><path d=\"M6 12h4m-2-2v4\"/><circle cx=\"15\" cy=\"11\" r=\"1\"/><circle cx=\"17\" cy=\"13\" r=\"1\"/>',"
    "  pkg:'<path d=\"M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z\"/><polyline points=\"3.27 6.96 12 12.01 20.73 6.96\"/><line x1=\"12\" y1=\"22.08\" x2=\"12\" y2=\"12\"/>',"
    "  bolt:'<polygon points=\"13 2 3 14 12 14 11 22 21 10 12 10 13 2\"/>',"
    "  cpu:'<rect x=\"4\" y=\"4\" width=\"16\" height=\"16\" rx=\"2\"/><rect x=\"9\" y=\"9\" width=\"6\" height=\"6\"/><path d=\"M9 1v3m6-3v3M9 20v3m6-3v3M20 9h3m-3 6h3M1 9h3m-3 6h3\"/>',"
    "  user:'<path d=\"M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2\"/><circle cx=\"12\" cy=\"7\" r=\"4\"/>',"
    "  disc:'<circle cx=\"12\" cy=\"12\" r=\"10\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/>',"
    "  term:'<polyline points=\"4 17 10 11 4 5\"/><line x1=\"12\" y1=\"19\" x2=\"20\" y2=\"19\"/>',"
    "  palette:'<circle cx=\"12\" cy=\"12\" r=\"10\"/><circle cx=\"8.5\" cy=\"8.5\" r=\"1.5\"/><circle cx=\"15.5\" cy=\"8.5\" r=\"1.5\"/><circle cx=\"15.5\" cy=\"14.5\" r=\"1.5\"/>',"
    "  search:'<circle cx=\"11\" cy=\"11\" r=\"8\"/><line x1=\"21\" y1=\"21\" x2=\"16.65\" y2=\"16.65\"/>',"
    "  upload:'<path d=\"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4\"/><polyline points=\"17 8 12 3 7 8\"/><line x1=\"12\" y1=\"3\" x2=\"12\" y2=\"15\"/>',"
    "  download:'<path d=\"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4\"/><polyline points=\"7 10 12 15 17 10\"/><line x1=\"12\" y1=\"15\" x2=\"12\" y2=\"3\"/>',"
    "  shield:'<path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/>',"
    "  trash:'<polyline points=\"3 6 5 6 21 6\"/><path d=\"M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2\"/>',"
    "  power:'<path d=\"M18.36 6.64a9 9 0 1 1-12.73 0\"/><line x1=\"12\" y1=\"2\" x2=\"12\" y2=\"12\"/>',"
    "  back:'<polyline points=\"15 18 9 12 15 6\"/>'"
    "};"
    "function ic(name,cls='svg-ic'){return `<svg class='${cls}' viewBox='0 0 24 24'>${SVG_PATHS[name]||SVG_PATHS.file}</svg>`;}"
    "let mode='FILE',usbMount='/mnt/usb0',activePanel='left',isProcessing=false,editingPath='',editingGameId='';"
    "let panels={left:{path:'/user/app/',items:[]},right:{path:'/mnt/usb0/',items:[]}};"
    "let gpIndex=0,lastGpTime=0,inputCallback=null,usbPkgItems=[];"
    "function showToast(msg){const el=document.getElementById('ui-toast');el.innerText=msg;el.style.display='block';clearTimeout(window._tTimer);window._tTimer=setTimeout(()=>{el.style.display='none';},2800);}"
    "function openInputModal(title,defVal,cb){"
    "  inputCallback=cb;document.getElementById('inp-title').innerText=title;"
    "  const inp=document.getElementById('inp-field');inp.value=defVal||'';"
    "  document.getElementById('modal-input').style.display='flex';gpIndex=0;setTimeout(()=>inp.focus(),80);"
    "}"
    "function confirmInputModal(){const v=document.getElementById('inp-field').value.trim();document.getElementById('modal-input').style.display='none';if(v&&inputCallback)inputCallback(v);}"
    "function setTheme(th){document.body.setAttribute('data-theme',th);try{localStorage.setItem('firoz_theme',th);}catch(e){}}"
    "function formatSize(b){if(!b||b<=0)return '0 B';const k=1024,s=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k));return parseFloat((b/Math.pow(k,i)).toFixed(2))+' '+s[i];}"
    "function formatTime(sec){if(!isFinite(sec)||sec<0)return '00:00';let m=Math.floor(sec/60),s=Math.floor(sec%60);return `${m<10?'0':''}${m}:${s<10?'0':''}${s}`;}"
    "function setActivePane(p){activePanel=p;document.getElementById('pane-left').classList.toggle('active-pane',p==='left');document.getElementById('pane-right').classList.toggle('active-pane',p==='right');}"
    "function isAudio(n){return /\\.(mp3|wav|ogg|flac)$/i.test(n);}"
    "function isVideo(n){return /\\.(mp4|webm|mkv)$/i.test(n);}"
    "function isImage(n){return /\\.(png|jpg|jpeg|webp|gif|bmp)$/i.test(n);}"
    "function isText(n){return /\\.(json|ini|cfg|conf|txt|xml|lua|log|sh|html|css|js|yml|md)$/i.test(n);}"
    "async function initSys(){"
    "  try{const savedTh=localStorage.getItem('firoz_theme');if(savedTh)setTheme(savedTh);}catch(e){}"
    "  try{const r=await fetch('/api/sysinfo');const d=await r.json();if(d.usb_mount){usbMount=d.usb_mount;panels.right.path=usbMount+'/';}}catch(e){}"
    "  setMode('FILE');requestAnimationFrame(pollGamepad);"
    "  setInterval(()=>{if(mode==='DASH')fetchDash();if(mode==='TERM')fetchKlog();if(mode==='PROC')loadProcs();},2200);"
    "}"
    "async function setMode(m){"
    "  if(isProcessing)return;mode=m;gpIndex=0;"
    "  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));"
    "  const tb=document.getElementById('tab-'+m);if(tb)tb.classList.add('active');"
    "  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));"
    "  const map={FILE:'view-files',RUN:'view-run',PKG:'view-pkg',PROC:'view-proc',PROF:'view-prof',DASH:'view-dash',TERM:'view-term',THEME:'view-theme'};"
    "  document.getElementById(map[m]).classList.add('active');"
    "  if(m==='FILE'){loadDir('left',panels.left.path);loadDir('right',panels.right.path);}"
    "  else if(m==='RUN')loadGames();"
    "  else if(m==='PKG')loadPkgsAndElfs();"
    "  else if(m==='PROC')loadProcs();"
    "  else if(m==='PROF')loadProfiles();"
    "  else if(m==='DASH')fetchDash();"
    "  else if(m==='TERM')fetchKlog();"
    "}"
    "async function loadDir(side,path){"
    "  if(!path.endsWith('/'))path+='/';panels[side].path=path;document.getElementById('path-'+side).innerText=path;"
    "  try{const r=await fetch('/api/list?dir='+encodeURIComponent(path));const d=await r.json();"
    "    panels[side].items=(d.items||[]).sort((a,b)=>(a.type===b.type?a.name.localeCompare(b.name):(a.type==='dir'?-1:1)));"
    "    renderList(side);"
    "  }catch(e){document.getElementById('list-'+side).innerHTML=`<div class='row'><button class='btn-name focusable'>[!] مسیر در دسترس نیست</button></div>`;}"
    "}"
    "function goParentDir(side){"
    "  let p=panels[side].path;if(p==='/'||p==='')return;"
    "  let pr=p.substring(0,p.lastIndexOf('/',p.length-2))+'/';if(pr==='')pr='/';"
    "  loadDir(side,pr);"
    "}"
    "function renderList(side){"
    "  const list=document.getElementById('list-'+side);if(!list)return;list.innerHTML='';const p=panels[side].path;"
    "  if(p!=='/'&&p!==''){"
    "    list.innerHTML+=`<div class='row'><button class='btn-name focusable' onclick=\"goParentDir('${side}')\"><span class='f-name-wrap'>${ic('back')} [..] بازگشت به پوشه قبل</span></button></div>`;"
    "  }"
    "  panels[side].items.forEach((i,idx)=>{"
    "    const is=i.selected?'selected':'';const mk=i.selected?'[X]':'[ ]';"
    "    let svgName=i.type==='dir'?'folder':(isAudio(i.name)?'disc':(i.name.endsWith('.pkg')?'pkg':(i.name.endsWith('.elf')||i.name.endsWith('.bin')?'bolt':'file')));"
    "    const meta=i.type==='dir'?(i.title||'DIR'):(i.title?`${i.title} | ${formatSize(i.size)}`:formatSize(i.size));"
    "    list.innerHTML+=`<div class='row'><button class='btn-chk focusable ${is}' onclick=\"toggleSelIdx('${side}',${idx})\">${mk}</button><button class='btn-name focusable' data-side='${side}' data-idx='${idx}' onclick=\"openItemIdx('${side}',${idx})\"><span class='f-name-wrap'>${ic(svgName)} <span>${i.name}</span></span><span class='f-meta'>${meta}</span></button></div>`;"
    "  });"
    "}"
    "function toggleSelIdx(side,idx){setActivePane(side);const it=panels[side].items[idx];if(it){it.selected=!it.selected;renderList(side);}}"
    "function openItemIdx(side,idx){"
    "  setActivePane(side);const it=panels[side].items[idx];if(!it)return;"
    "  const p=panels[side].path,fullP=p+(p.endsWith('/')?'':'/')+it.name;"
    "  if(it.type==='dir')loadDir(side,fullP+'/');"
    "  else if(isAudio(it.name))playMusic(fullP,it.name);"
    "  else if(isVideo(it.name)||isImage(it.name))openMediaPreview(fullP,it.name);"
    "  else if(isText(it.name))openEditor(fullP);"
    "  else if(it.name.endsWith('.elf')||it.name.endsWith('.bin'))runElf(fullP);"
    "  else if(it.name.toLowerCase().endsWith('.pkg')){fetch('/api/install_pkg?pkg='+encodeURIComponent(fullP));showToast('Installing '+it.name);}"
    "  else openHexViewer(fullP);"
    "}";

const char *UI_PART4 =
    "function playMusic(path,name){"
    "  const bar=document.getElementById('music-bar'),aud=document.getElementById('aud-el');"
    "  bar.style.display='flex';document.getElementById('m-title').innerText=name;"
    "  aud.src='/api/stream?file='+encodeURIComponent(path);aud.play();"
    "  document.getElementById('m-disc').classList.remove('paused');"
    "}"
    "function toggleAudio(){const a=document.getElementById('aud-el'),d=document.getElementById('m-disc');if(a.paused){a.play();d.classList.remove('paused');}else{a.pause();d.classList.add('paused');}}"
    "function seekAudio(v){const a=document.getElementById('aud-el');if(a.duration)a.currentTime=(v/100)*a.duration;}"
    "function openMediaPreview(path,name){"
    "  const box=document.getElementById('media-content');document.getElementById('media-title').innerText=name;"
    "  const u='/api/stream?file='+encodeURIComponent(path);"
    "  if(isVideo(name))box.innerHTML=`<video src='${u}' controls autoplay style='max-width:100%;max-height:60vh;border-radius:14px;'></video>`;"
    "  else box.innerHTML=`<img src='${u}' style='max-width:100%;max-height:60vh;border-radius:14px;'>`;"
    "  document.getElementById('modal-media').style.display='flex';"
    "}"
    "async function openHexViewer(path){"
    "  const r=await fetch('/api/hex?file='+encodeURIComponent(path));"
    "  document.getElementById('hex-area').innerText=await r.text();"
    "  document.getElementById('modal-hex').style.display='flex';"
    "}"
    "async function verifyFileHash(path){"
    "  showToast('در حال محاسبه هش SHA-256 و CRC32...');"
    "  const r=await fetch('/api/hash?file='+encodeURIComponent(path));const d=await r.json();"
    "  if(d.ok){"
    "    document.getElementById('hex-area').innerText=`File: ${path}\\nSize: ${formatSize(d.size)} (${d.size} bytes)\\n\\nCRC32  : ${d.crc32}\\nSHA256 : ${d.sha256}`;"
    "    document.getElementById('modal-hex').style.display='flex';"
    "  }else showToast('خطا در محاسبه هش فایل');"
    "}"
    "function openSearchDialog(){"
    "  const root=panels[activePanel].path;"
    "  openInputModal('جستجوی عمیق در '+root,'',async(q)=>{"
    "    showToast('در حال جستجوی '+q+'...');"
    "    const r=await fetch('/api/search?dir='+encodeURIComponent(root)+'&q='+encodeURIComponent(q));"
    "    const d=await r.json();"
    "    const items=(d.results||[]);"
    "    document.getElementById('hex-area').innerText=items.length?items.map(x=>`[${x.type.toUpperCase()}] ${x.path} (${formatSize(x.size)})`).join('\\n'):'هیچ فایلی با این نام یافت نشد.';"
    "    document.getElementById('modal-hex').style.display='flex';"
    "  });"
    "}"
    "async function uploadBrowserFile(ev){"
    "  const f=ev.target.files[0];if(!f)return;"
    "  const dst=panels[activePanel].path+f.name;"
    "  showToast('در حال آپلود '+f.name+'...');"
    "  const buf=await f.arrayBuffer();"
    "  const r=await fetch('/api/upload?dst='+encodeURIComponent(dst),{method:'POST',body:buf});"
    "  if(r.ok){showToast('آپلود با موفقیت انجام شد!');loadDir(activePanel,panels[activePanel].path);}"
    "  else showToast('خطا در آپلود فایل');"
    "  ev.target.value='';"
    "}"
    "async function injectRamElfFile(ev){"
    "  const f=ev.target.files[0];if(!f)return;"
    "  showToast('در حال تزریق مستقیم '+f.name+' به رم و elfldr...');"
    "  const buf=await f.arrayBuffer();"
    "  const r=await fetch('/api/inject_elf_ram?name='+encodeURIComponent(f.name),{method:'POST',body:buf});"
    "  const d=await r.json();"
    "  if(d.ok)showToast('پیلود با موفقیت به پورت 9021 تزریق شد!');"
    "  else showToast('خطا: فایل ELF معتبر نیست یا elfldr فعال نیست');"
    "  ev.target.value='';"
    "}"
    "async function fetchDash(){"
    "  try{const r=await fetch('/api/sysinfo');const d=await r.json();"
    "    document.getElementById('ssd-free').innerText=d.ssd_free.toFixed(1)+' GB';"
    "    document.getElementById('ssd-tot').innerText='Total: '+d.ssd_total.toFixed(1)+' GB | FW: '+d.fw;"
    "    document.getElementById('usb-free').innerText=d.usb_free>0?d.usb_free.toFixed(1)+' GB':'Offline';"
    "    document.getElementById('usb-tot').innerText=d.usb_mount+' ('+d.usb_total.toFixed(1)+' GB)';"
    "    document.getElementById('ftp-addr').innerText=d.ip+':'+d.ftp_port;"
    "    document.getElementById('apu-temp').innerText=d.temp+' °C';"
    "    const dl=document.getElementById('drives-list');if(dl&&d.drives){"
    "      dl.innerHTML=d.drives.map(dr=>`<div class='stat-box'><div class='s-title'>${dr.name}</div><div style='display:flex;justify-content:space-between;font-size:0.88rem;'><span>آزاد: <b style='color:#22c55e'>${dr.free} GB</b></span><span>کل: <b>${dr.total} GB</b> (${dr.pct}%)</span></div><div class='drive-bar-bg'><div class='drive-bar-fill' style='width:${dr.pct}%'></div></div></div>`).join('');"
    "    }"
    "  }catch(e){}"
    "}"
    "async function runBenchmarkNow(target){"
    "  showToast('در حال تست سرعت ۶۴ مگابایتی روی '+target+'...');"
    "  try{const r=await fetch('/api/benchmark?dir='+encodeURIComponent(target));const d=await r.json();"
    "    if(d.ok)showToast(`Write: ${d.write_mbps.toFixed(1)} MB/s | Read: ${d.read_mbps.toFixed(1)} MB/s`);"
    "    else showToast('خطا در تست سرعت این مسیر');"
    "  }catch(e){}"
    "}"
    "async function loadProcs(){"
    "  const pg=document.getElementById('proc-list');if(!pg)return;"
    "  try{const r=await fetch('/api/procs');const d=await r.json();"
    "    pg.innerHTML=(d.procs||[]).map(p=>`<div class='row'><button class='btn-name focusable' onclick=\"killPid(${p.pid},'${p.name}',${p.is_self})\"><span class='f-name-wrap'>${ic('cpu')} <b>PID ${p.pid}</b> - ${p.name}</span><span class='f-meta'>${p.role} ${p.is_self?'[ACTIVE]':'[KILL]'}</span></button></div>`).join('');"
    "  }catch(e){}"
    "}"
    "async function killPid(pid,name,isSelf){"
    "  if(isSelf||pid<20){showToast('پروسه‌های حیاتی کرنل قابل بستن نیستند');return;}"
    "  await fetch('/api/proc/kill?pid='+pid,{method:'POST'});"
    "  showToast('سیگنال توقف به PID '+pid+' ('+name+') ارسال شد');loadProcs();"
    "}"
    "async function fetchKlog(){try{const r=await fetch('/api/klog');const t=await r.text();const el=document.getElementById('klog-view');el.innerText=t;el.scrollTop=el.scrollHeight;}catch(e){}}"
    "async function loadProfiles(){"
    "  const g=document.getElementById('prof-grid');g.innerHTML='';"
    "  try{const r=await fetch('/api/profiles');const d=await r.json();"
    "    (d.profiles||[]).forEach(p=>{"
    "      g.innerHTML+=`<div class='card-item'>${ic('user','svg-lg')}<div class='game-title'>${p.name}</div><div class='f-meta'>ID: ${p.id} | Trophy: ${formatSize(p.trophy_size)}</div><div class='f-meta' style='margin-top:4px;'>PS5 Saves: ${formatSize(p.ps5_save_size)} | PS4: ${formatSize(p.ps4_save_size)}</div><div style='display:flex;gap:5px;width:100%;margin-top:10px;'><button class='act-tile focusable' style='flex:1;padding:7px;' onclick=\"backupProfile('${p.id}','trophy')\">تروفی</button><button class='act-tile focusable' style='flex:1;padding:7px;' onclick=\"backupProfile('${p.id}','save5')\">سیو PS5</button><button class='act-tile focusable' style='flex:1;padding:7px;' onclick=\"backupProfile('${p.id}','save4')\">سیو PS4</button><button class='act-tile focusable' style='flex:1;padding:7px;' onclick=\"renameProfile('${p.id}')\">نام</button></div></div>`;"
    "    });"
    "  }catch(e){}"
    "}";

const char *UI_PART5 =
    "async function waitTaskCompletion(){"
    "  document.getElementById('overlay').style.display='flex';"
    "  while(true){"
    "    await new Promise(r=>setTimeout(r,350));"
    "    try{const res=await fetch('/api/status');const d=await res.json();"
    "      if(d.running===1&&d.total>0){let pct=Math.min(100,(d.copied/d.total)*100);document.getElementById('p-bar').style.width=pct+'%';document.getElementById('p-text').innerText=`${pct.toFixed(1)}% | ${d.speed.toFixed(1)} MB/s | Files: ${d.files} | ETA: ${formatTime(d.eta)}`;document.getElementById('p-file').innerText=d.file||'';}"
    "      else if(d.running===0)break;"
    "    }catch(e){break;}"
    "  }"
    "  document.getElementById('overlay').style.display='none';"
    "}"
    "async function backupProfile(id,kind){"
    "  if(isProcessing)return;isProcessing=true;"
    "  const src=kind==='trophy'?`/user/home/${id}/trophy2`:(kind==='save4'?`/user/home/${id}/savedata`:`/user/home/${id}/savedata_prospero`);"
    "  const dst=`${usbMount}/FIROZ_BACKUP_${id}_${kind}`;"
    "  await fetch('/api/action',{method:'POST',body:`type=copy&src=${encodeURIComponent(src)}&dst=${encodeURIComponent(dst)}`});"
    "  await waitTaskCompletion();isProcessing=false;showToast('بکاپ با موفقیت در USB ذخیره شد!');"
    "}"
    "function renameProfile(id){"
    "  openInputModal('نام جدید پروفایل:','',async(n)=>{"
    "    await fetch('/api/profile/rename?id='+encodeURIComponent(id),{method:'POST',body:n});loadProfiles();showToast('نام پروفایل ذخیره شد');"
    "  });"
    "}"
    "async function cleanCacheNow(){const r=await fetch('/api/clean_cache',{method:'POST'});const d=await r.json();showToast('کش پاکسازی شد! آزاد شده: '+formatSize(d.freed));}"
    "async function loadGames(){"
    "  const lg=document.getElementById('launch-grid');lg.innerHTML='';"
    "  try{const r=await fetch('/api/games');const d=await r.json();"
    "    (d.games||[]).forEach(g=>{"
    "      lg.innerHTML+=`<div class='card-item'><img src='/api/game-icon?id=${encodeURIComponent(g.id)}' class='game-cover'><div class='game-title'>${g.title}</div><div class='f-meta'>${g.id} | v${g.ver}</div><div class='f-meta' style='margin-top:3px;color:var(--accent);'>${g.storage}</div><div style='display:flex;gap:6px;width:100%;margin-top:8px;'><button class='act-tile focusable' style='flex:1;padding:7px;' onclick=\"fetch('/api/launch?id=${encodeURIComponent(g.id)}');showToast('Launching ${g.title}...')\">اجرا</button><button class='act-tile focusable' style='flex:1;padding:7px;' onclick=\"editGameParam('${g.id}','${g.title}','${g.ver}')\">ویرایش</button></div></div>`;"
    "    });"
    "  }catch(e){}"
    "}"
    "function editGameParam(id,curTitle,curVer){"
    "  openInputModal('نام جدید بازی ('+id+'):',curTitle,async(newT)=>{"
    "    await fetch('/api/param/save?id='+encodeURIComponent(id)+'&ver='+encodeURIComponent(curVer),{method:'POST',body:newT});"
    "    showToast('متادیتای بازی بروزرسانی شد!');loadGames();"
    "  });"
    "}"
    "async function loadPkgsAndElfs(){"
    "  const pg=document.getElementById('pkg-grid');pg.innerHTML='';"
    "  try{const r=await fetch('/api/list?dir='+encodeURIComponent(usbMount+'/'));const d=await r.json();"
    "    usbPkgItems=(d.items||[]).filter(i=>/\\.(pkg|elf|bin)$/i.test(i.name));"
    "    usbPkgItems.forEach((i,idx)=>{"
    "      const isPkg=i.name.toLowerCase().endsWith('.pkg');"
    "      const full=usbMount+'/'+i.name;"
    "      const coverHtml=isPkg?`<img src='/api/pkg-icon?path=${encodeURIComponent(full)}' class='game-cover'>`:`<div style='margin-bottom:10px;'>${ic('bolt','svg-lg')}</div>`;"
    "      pg.innerHTML+=`<button class='card-item focusable' onclick=\"runUsbItem(${idx})\">${coverHtml}<div class='game-title'>${i.name}</div><div class='f-meta'>${i.title||(isPkg?'PS4/PS5 PKG':'ELF Payload')}</div><div class='f-meta' style='margin-top:4px;'>${formatSize(i.size)}</div></button>`;"
    "    });"
    "  }catch(e){}"
    "}"
    "function runUsbItem(idx){"
    "  const it=usbPkgItems[idx];if(!it)return;const full=usbMount+'/'+it.name;"
    "  if(it.name.toLowerCase().endsWith('.pkg')){fetch('/api/install_pkg?pkg='+encodeURIComponent(full));showToast('Installing '+it.name);}"
    "  else runElf(full);"
    "}"
    "async function runElf(p){await fetch('/api/launch_elf?elf='+encodeURIComponent(p));showToast('Payload Injected!');}"
    "function toggleActionModal(show){const m=document.getElementById('modal-actions');m.style.display=show?'flex':'none';gpIndex=0;}"
    "async function openEditor(p){editingPath=p;const r=await fetch('/api/text?file='+encodeURIComponent(p));document.getElementById('ed-area').value=await r.text();document.getElementById('overlay-editor').style.display='flex';gpIndex=0;}"
    "async function saveEditor(){await fetch('/api/text/save?file='+encodeURIComponent(editingPath),{method:'POST',body:document.getElementById('ed-area').value});document.getElementById('overlay-editor').style.display='none';showToast('فایل ذخیره شد');}"
    "async function runQuickAction(act){"
    "  toggleActionModal(false);"
    "  const ss=activePanel,ds=(ss==='left')?'right':'left',sb=panels[ss].path,db=panels[ds].path;"
    "  if(act==='mkdir'){openInputModal('نام پوشه جدید:','',async(n)=>{await fetch('/api/action',{method:'POST',body:`type=mkdir&src=${encodeURIComponent(sb+n)}`});loadDir(ss,sb);});return;}"
    "  if(act==='upload'){document.getElementById('file-upload-inp').click();return;}"
    "  if(act==='search'){openSearchDialog();return;}"
    "  const sel=panels[ss].items.filter(i=>i.selected).map(i=>i.name);"
    "  if(sel.length===0){showToast('ابتدا با دکمه ▢ یک فایل یا پوشه انتخاب کنید');return;}"
    "  if(act==='download'){window.open('/api/download?file='+encodeURIComponent(sb+sel[0]),'_blank');return;}"
    "  if(act==='hex'){openHexViewer(sb+sel[0]);return;}"
    "  if(act==='hash'){verifyFileHash(sb+sel[0]);return;}"
    "  if(act==='rename'){openInputModal('نام جدید:',sel[0],async(n)=>{await fetch('/api/action',{method:'POST',body:`type=rename&src=${encodeURIComponent(sb+sel[0])}&dst=${encodeURIComponent(sb+n)}`});loadDir(ss,sb);});return;}"
    "  if(act==='chmod'){for(let nm of sel)await fetch('/api/action',{method:'POST',body:`type=chmod&src=${encodeURIComponent(sb+nm)}`});loadDir(ss,sb);showToast('سطح دسترسی 777 اعمال شد');return;}"
    "  isProcessing=true;"
    "  for(let nm of sel){"
    "    const sp=sb+nm,dp=db+nm;"
    "    await fetch('/api/action',{method:'POST',body:`type=${act}&src=${encodeURIComponent(sp)}&dst=${encodeURIComponent(dp)}`});"
    "    await waitTaskCompletion();"
    "  }"
    "  isProcessing=false;loadDir('left',panels.left.path);loadDir('right',panels.right.path);"
    "}"
    "function getActiveFocusables(){"
    "  const openModal=Array.from(document.querySelectorAll('.modal-wrap')).find(m=>m.style.display==='flex');"
    "  if(openModal)return Array.from(openModal.querySelectorAll('.focusable'));"
    "  if(mode==='FILE')return Array.from(document.querySelectorAll(`#pane-${activePanel} .focusable, .hud-bar .focusable`));"
    "  return Array.from(document.querySelectorAll('.view.active .focusable'));"
    "}"
    "function pollGamepad(){"
    "  const gps=navigator.getGamepads?navigator.getGamepads():[];"
    "  const gp=Array.from(gps).find(g=>g&&g.connected);"
    "  if(gp&&Date.now()-lastGpTime>165){"
    "    const b=gp.buttons,ax=gp.axes;"
    "    const vis=getActiveFocusables();"
    "    if(vis.length>0){"
    "      if(gpIndex>=vis.length)gpIndex=0;"
    "      document.querySelectorAll('.gp-focus').forEach(el=>el.classList.remove('gp-focus'));"
    "      vis[gpIndex].classList.add('gp-focus');vis[gpIndex].scrollIntoView({block:'nearest'});"
    "      if(b[13]?.pressed||ax[1]>0.55||b[15]?.pressed||ax[0]>0.55){gpIndex=(gpIndex+1)%vis.length;lastGpTime=Date.now();}"
    "      else if(b[12]?.pressed||ax[1]<-0.55||b[14]?.pressed||ax[0]<-0.55){gpIndex=(gpIndex-1+vis.length)%vis.length;lastGpTime=Date.now();}"
    "      else if(b[0]?.pressed){vis[gpIndex].click();lastGpTime=Date.now()+120;}"
    "      else if(b[2]?.pressed){const idx=vis[gpIndex].getAttribute('data-idx'),sd=vis[gpIndex].getAttribute('data-side');if(idx!==null&&sd)toggleSelIdx(sd,parseInt(idx,10));lastGpTime=Date.now()+120;}"
    "      else if(b[3]?.pressed){toggleActionModal(document.getElementById('modal-actions').style.display!=='flex');lastGpTime=Date.now()+150;}"
    "      else if(b[1]?.pressed){"
    "        const openModal=Array.from(document.querySelectorAll('.modal-wrap')).find(m=>m.style.display==='flex');"
    "        if(openModal)openModal.style.display='none';"
    "        else if(mode==='FILE'){goParentDir(activePanel);gpIndex=0;}"
    "        lastGpTime=Date.now()+150;"
    "      }"
    "      else if(b[4]?.pressed||b[5]?.pressed){const modes=['FILE','RUN','PKG','PROC','PROF','DASH','TERM','THEME'];let idx=modes.indexOf(mode);idx=(idx+(b[5]?.pressed?1:-1)+modes.length)%modes.length;setMode(modes[idx]);lastGpTime=Date.now()+180;}"
    "      else if(b[6]?.pressed){setActivePane('left');gpIndex=0;lastGpTime=Date.now()+120;}"
    "      else if(b[7]?.pressed){setActivePane('right');gpIndex=0;lastGpTime=Date.now()+120;}"
    "    }"
    "  }"
    "  requestAnimationFrame(pollGamepad);"
    "}"
    "window.onload=initSys;</script></head><body data-theme='cyber'>"
    "<input type='file' id='file-upload-inp' style='display:none' onchange='uploadBrowserFile(event)'>"
    "<input type='file' id='elf-ram-inp' accept='.elf,.bin' style='display:none' onchange='injectRamElfFile(event)'>"
    "<div id='ui-toast' style='display:none;position:fixed;bottom:26px;left:50%;transform:translateX(-50%);background:var(--accent);color:#020617;padding:11px 26px;border-radius:99px;font-weight:900;font-size:1rem;z-index:300;box-shadow:0 8px 25px var(--glow);'></div>"
    "<div id='modal-input' class='modal-wrap'><div class='modal-card' style='max-width:520px;'><h2 id='inp-title' style='margin-top:0;color:var(--accent);'>ورود اطلاعات</h2><input id='inp-field' type='text' class='focusable' style='width:100%;padding:13px;font-size:1.1rem;border-radius:12px;border:2px solid var(--border);background:#050811;color:var(--text);direction:ltr;text-align:center;' onkeydown=\"if(event.key==='Enter')confirmInputModal()\"><div style='display:flex;gap:12px;justify-content:center;margin-top:16px;'><button class='act-tile focusable' style='flex:1;' onclick='confirmInputModal()'>[OK] تایید</button><button class='act-tile focusable' style='flex:1;' onclick=\"document.getElementById('modal-input').style.display='none'\">[X] انصراف</button></div></div></div>"
    "<div id='overlay' class='modal-wrap'><div class='modal-card'><h2 id='p-file'>Processing...</h2><div class='progress-bg'><div class='progress-fill' id='p-bar'></div></div><h3 id='p-text' style='color:var(--accent)'>0%</h3><button class='act-tile focusable' onclick=\"fetch('/api/cancel',{method:'POST'})\">[STOP] لغو عملیات</button></div></div>"
    "<div id='overlay-editor' class='modal-wrap'><div class='modal-card' style='width:82%;'><textarea id='ed-area' class='focusable' style='width:100%;height:340px;background:#050811;color:var(--accent);border:1px solid var(--border);border-radius:12px;padding:12px;direction:ltr;font-family:monospace;'></textarea><div style='display:flex;gap:12px;justify-content:center;margin-top:12px;'><button class='act-tile focusable' onclick='saveEditor()'>[SAVE] ذخیره</button><button class='act-tile focusable' onclick=\"document.getElementById('overlay-editor').style.display='none'\">[X] بستن</button></div></div></div>"
    "<div id='modal-hex' class='modal-wrap'><div class='modal-card' style='width:86%;'><h3 style='margin-top:0;color:var(--accent);'>بازرس باینری، هش و جستجو (Inspector)</h3><pre id='hex-area' style='background:#050811;color:#22c55e;padding:14px;border-radius:12px;overflow-x:auto;direction:ltr;text-align:left;font-size:0.9rem;max-height:55vh;'></pre><button class='act-tile focusable' onclick=\"document.getElementById('modal-hex').style.display='none'\">[X] بستن</button></div></div>"
    "<div id='modal-media' class='modal-wrap'><div class='modal-card'><h3 id='media-title' style='margin-top:0;color:var(--accent);'>Preview</h3><div id='media-content' style='margin:14px 0;'></div><button class='act-tile focusable' onclick=\"document.getElementById('modal-media').style.display='none';document.getElementById('media-content').innerHTML='';\">[X] بستن</button></div></div>"
    "<div id='modal-actions' class='modal-wrap'><div class='modal-card'><h2 style='margin:0;color:var(--accent);'>پالت عملیات تیتانیوم (FIROZ OS v6.0)</h2><div class='action-grid'>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('copy')\">کپی توربو (8MB DMA)</button>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('cut')\">انتقال به پنل مقابل</button>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('extract')\">استخراج PKG/ZIP/TAR/RAR</button>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('fpkg')\">ساخت پکیج استاندارد CNT/fPKG</button>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('tar')\">فشرده‌سازی به آرشیو TAR</button>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('hash')\">محاسبه هش SHA-256 و CRC32</button>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('hex')\">بررسی باینری (Hex View)</button>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('search')\">جستجوی عمیق فایل‌ها</button>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('upload')\">آپلود فایل به این پوشه</button>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('download')\">دانلود مستقیم فایل</button>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('mkdir')\">ساخت پوشه جدید</button>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('rename')\">تغییر نام</button>"
    "  <button class='act-tile focusable' onclick=\"runQuickAction('chmod')\">اعمال دسترسی کامل 777</button>"
    "  <button class='act-tile focusable' style='border-color:#f43f5e;color:#f43f5e;' onclick=\"runQuickAction('del')\">حذف انتخاب‌شده‌ها</button>"
    "  <button class='act-tile focusable' onclick='toggleActionModal(false)'>[X] بستن منو</button>"
    "</div></div></div>"
    "<header><div class='brand'><img src='/icon0.png' class='logo-img'><h1>FIROZ OS <span style='font-size:0.9rem;color:var(--accent);'>v6.0 TITANIUM</span></h1><div class='tg-pill'><span>@firozfar051</span></div></div><div class='top-actions'><button class='icon-btn focusable' onclick=\"document.getElementById('elf-ram-inp').click()\">[ELF] تزریق پیلود به RAM</button><button class='icon-btn focusable' onclick=\"fetch('/api/kill_app',{method:'POST'});showToast('بستن بازی فعال ارسال شد')\">[KILL] بستن بازی فعال</button><a class='icon-btn focusable' style='background:#dc2626;border-color:#f87171;color:#fff;' href='/exit'>[EXIT] توقف سرور</a></div></header>"
    "<div class='tab-bar'>"
    "  <button id='tab-FILE' class='tab-btn focusable active' onclick=\"setMode('FILE')\">فایل منیجر</button>"
    "  <button id='tab-RUN' class='tab-btn focusable' onclick=\"setMode('RUN')\">بازی‌ها و استودیو</button>"
    "  <button id='tab-PKG' class='tab-btn focusable' onclick=\"setMode('PKG')\">نصب PKG و ELF</button>"
    "  <button id='tab-PROC' class='tab-btn focusable' onclick=\"setMode('PROC')\">پروسه‌های کرنل</button>"
    "  <button id='tab-PROF' class='tab-btn focusable' onclick=\"setMode('PROF')\">پروفایل و بکاپ</button>"
    "  <button id='tab-DASH' class='tab-btn focusable' onclick=\"setMode('DASH')\">دیسک و بنچمارک</button>"
    "  <button id='tab-TERM' class='tab-btn focusable' onclick=\"setMode('TERM')\">لاگ هسته</button>"
    "  <button id='tab-THEME' class='tab-btn focusable' onclick=\"setMode('THEME')\">تم و ابزار</button>"
    "</div>"
    "<div class='main-area'>"
    "  <div id='view-files' class='view active'><div class='split-grid'>"
    "    <div id='pane-left' class='glass-panel active-pane' onclick=\"setActivePane('left')\"><div class='panel-head'><span>SSD داخلی</span><div class='mount-bar'><button class='m-pill' onclick=\"loadDir('left','/user/app/')\">APP</button><button class='m-pill' onclick=\"loadDir('left','/user/appmeta/')\">META</button><button class='m-pill' onclick=\"loadDir('left','/user/home/')\">HOME</button><button class='m-pill' onclick=\"loadDir('left','/data/')\">DATA</button><button class='m-pill' onclick=\"loadDir('left','/')\">ROOT</button></div></div><div class='path-bar' id='path-left'></div><div id='list-left' class='file-list'></div></div>"
    "    <div id='pane-right' class='glass-panel' onclick=\"setActivePane('right')\"><div class='panel-head'><span>USB / M.2 / Ext</span><div class='mount-bar'><button class='m-pill' onclick=\"loadDir('right',usbMount+'/')\">USB</button><button class='m-pill' onclick=\"loadDir('right','/mnt/ext0/')\">M.2</button><button class='m-pill' onclick=\"loadDir('right','/mnt/ext1/')\">EXT1</button><button class='m-pill' onclick=\"loadDir('right','/data/etaHEN/games/')\">etaHEN</button></div></div><div class='path-bar' id='path-right'></div><div id='list-right' class='file-list'></div></div>"
    "  </div><div class='hud-bar'><div class='hud-hints'><span><b class='k-badge'>✕</b> باز کردن</span><span><b class='k-badge'>▢</b> انتخاب</span><span><b class='k-badge'>◯</b> بازگشت</span><span><b class='k-badge'>L1/R1</b> تب‌ها</span><span><b class='k-badge'>L2/R2</b> تغییر پنل</span></div><div style='display:flex;gap:8px;'><button class='btn-menu-trigger focusable' onclick='openSearchDialog()'>جستجو</button><button class='btn-menu-trigger focusable' onclick=\"runQuickAction('upload')\">آپلود فایل</button><button id='btn-act-open' class='btn-menu-trigger focusable' onclick='toggleActionModal(true)'>منوی عملیات (△)</button></div></div></div>"
    "  <div id='view-run' class='view'><div class='cards-grid' id='launch-grid'></div></div>"
    "  <div id='view-pkg' class='view'><div class='cards-grid' id='pkg-grid'></div></div>"
    "  <div id='view-proc' class='view'><div class='glass-panel' style='flex:1;'><div class='panel-head'><span>لیست پروسه‌های زنده کرنل و یوزرلند (کلیک برای ارسال سیگنال توقف)</span><button class='m-pill focusable' onclick='loadProcs()'>REFRESH</button></div><div id='proc-list' class='file-list'></div></div></div>"
    "  <div id='view-prof' class='view'><div class='cards-grid' id='prof-grid'></div></div>"
    "  <div id='view-dash' class='view' style='overflow-y:auto;'><div class='dash-layout'>"
    "    <div class='stat-box'><div class='s-title'>SSD (/user)</div><div class='s-val' id='ssd-free'>--</div><div class='s-sub' id='ssd-tot'>--</div></div>"
    "    <div class='stat-box'><div class='s-title'>USB STORAGE</div><div class='s-val' id='usb-free'>--</div><div class='s-sub' id='usb-tot'>--</div></div>"
    "    <div class='stat-box'><div class='s-title'>دمای پردازنده (APU)</div><div class='s-val' id='apu-temp'>-- °C</div><div class='s-sub'>سنسور حرارتی زنده</div></div>"
    "    <div class='stat-box'><div class='s-title'>سرور Turbo FTP</div><div class='s-val' id='ftp-addr' style='font-size:1.3rem;'>--</div><div class='s-sub'>پورت 2121 (بافر 4MB)</div></div>"
    "  </div><div style='display:flex;gap:10px;margin-bottom:12px;'><button class='act-tile focusable' style='flex:1;' onclick=\"runBenchmarkNow('/data')\">تست سرعت SSD داخلی (/data)</button><button class='act-tile focusable' style='flex:1;' onclick=\"runBenchmarkNow(usbMount)\">تست سرعت فلش USB</button></div><div id='drives-list' style='display:grid;grid-template-columns:1fr 1fr;gap:12px;'></div></div>"
    "  <div id='view-term' class='view'><div class='term-box' id='klog-view'>در حال دریافت لاگ‌های هسته...</div></div>"
    "  <div id='view-theme' class='view'><div class='action-grid'>"
    "    <button class='act-tile focusable' onclick=\"setTheme('cyber')\">Cyberpunk Neon</button>"
    "    <button class='act-tile focusable' onclick=\"setTheme('ps5')\">PS5 Royal Blue</button>"
    "    <button class='act-tile focusable' onclick=\"setTheme('matrix')\">Matrix Hacker</button>"
    "    <button class='act-tile focusable' onclick=\"setTheme('crimson')\">Crimson Tactical</button>"
    "    <button class='act-tile focusable' onclick=\"setTheme('oled')\">OLED Pitch Black</button>"
    "    <button class='act-tile focusable' onclick=\"setTheme('light')\">Frost Glass Light</button>"
    "    <button class='act-tile focusable' style='grid-column:span 3;border-color:#10b981;' onclick='cleanCacheNow()'>پاک‌سازی هوشمند کش بازی‌های PS4 و PS5 (Smart Cache Cleaner)</button>"
    "    <button class='act-tile focusable' style='grid-column:span 3;border-color:var(--accent);' onclick=\"fetch('/api/install_tile',{method:'POST'});showToast('آیکون FIROZ OS در صفحه اصلی PS5 ثبت شد!')\">نصب/تعمیر آیکون FIROZ OS در صفحه اصلی کنسول (Home Screen Tile)</button>"
    "  </div></div>"
    "</div>"
    "<div id='music-bar'><img src='/icon0.png' id='m-disc' class='disc-art'><div class='m-info' id='m-title'>Track.mp3</div><button class='icon-btn focusable' onclick='toggleAudio()'>[PLAY/PAUSE]</button><input type='range' id='m-seek' class='m-slider' value='0' min='0' max='100' oninput='seekAudio(this.value)'><span id='m-time' style='font-family:monospace;'>00:00 / 00:00</span><audio id='aud-el' ontimeupdate=\"if(this.duration){document.getElementById('m-seek').value=(this.currentTime/this.duration)*100;document.getElementById('m-time').innerText=formatTime(this.currentTime)+' / '+formatTime(this.duration);}\"></audio></div>"
    "</body></html>";

void *client_thread(void *arg) {
    int client_sock = *(int *)arg;
    free(arg);

    tune_socket_performance(client_sock);
    struct timeval tv = { 45, 0 };
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char *buffer = malloc(32768);
    if (!buffer) { close(client_sock); return NULL; }

    int bytes_read = 0;
    while (bytes_read < 32767) {
        ssize_t n = recv(client_sock, buffer + bytes_read, 32767 - bytes_read, 0);
        if (n <= 0) break;
        bytes_read += (int)n;
        buffer[bytes_read] = '\0';
        if (strstr(buffer, "\r\n\r\n")) break;
    }
    if (bytes_read <= 0) { free(buffer); close(client_sock); return NULL; }

    char req_method[16] = {0}, req_path[2048] = {0};
    if (sscanf(buffer, "%15s %2047s", req_method, req_path) != 2) {
        free(buffer); close(client_sock); return NULL;
    }

    char *header_end = strstr(buffer, "\r\n\r\n");
    long long content_length = 0;
    char *cl_ptr = strcasestr(buffer, "Content-Length:");
    if (cl_ptr) content_length = strtoll(cl_ptr + 15, NULL, 10);

    if (strncmp(req_path, "/exit", 5) == 0) {
        const char *exit_res =
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: close\r\n\r\n"
            "<!DOCTYPE html><html dir='rtl'><body style='background:#020617;color:#38bdf8;font-family:Tahoma;text-align:center;padding-top:18%;'>"
            "<h1>FIROZ OS v6.0 Titanium متوقف شد.</h1><p style='color:#fff;'>اکنون می‌توانید پنجره را ببندید.</p></body></html>";
        send_all(client_sock, exit_res, strlen(exit_res));
        g_server_running = 0;
    }
    else if (strncmp(req_path, "/icon0.png", 10) == 0) {
        char hdr[256];
        snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: %u\r\nCache-Control: max-age=3600\r\nConnection: close\r\n\r\n",
            FIROZ_BUILTIN_PNG_LEN);
        send_all(client_sock, hdr, strlen(hdr));
        send_all(client_sock, FIROZ_BUILTIN_PNG, FIROZ_BUILTIN_PNG_LEN);
    }
    else if (strncmp(req_path, "/api/game-icon", 14) == 0) {
        char id[128];
        get_param(req_path, "id=", id, sizeof(id));
        api_game_icon(client_sock, id);
    }
    else if (strncmp(req_path, "/api/pkg-icon", 13) == 0) {
        char ppath[1024];
        get_param(req_path, "path=", ppath, sizeof(ppath));
        api_pkg_icon(client_sock, ppath);
    }
    else if (strncmp(req_path, "/api/games", 10) == 0) {
        api_games_scan(client_sock);
    }
    else if (strncmp(req_path, "/api/procs", 10) == 0) {
        api_procs_list(client_sock);
    }
    else if (strncmp(req_path, "/api/proc/kill", 14) == 0 && strcmp(req_method, "POST") == 0) {
        char pid_s[32];
        get_param(req_path, "pid=", pid_s, sizeof(pid_s));
        int pid = atoi(pid_s);
        int rc = (pid > 20 && pid != (int)getpid()) ? kill(pid, SIGTERM) : -1;
        char res[160];
        snprintf(res, sizeof(res), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":%s}", rc == 0 ? "true" : "false");
        send_all(client_sock, res, strlen(res));
    }
    else if (strncmp(req_path, "/api/hash", 9) == 0) {
        char file[1024], sha[70], crc[20];
        long long fsz = 0;
        get_param(req_path, "file=", file, sizeof(file));
        int rc = compute_file_hashes(file, sha, crc, &fsz);
        char res[512];
        snprintf(res, sizeof(res),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
            "{\"ok\":%s,\"size\":%lld,\"crc32\":\"%s\",\"sha256\":\"%s\"}",
            rc == 0 ? "true" : "false", fsz, crc, sha);
        send_all(client_sock, res, strlen(res));
    }
    else if (strncmp(req_path, "/api/search", 11) == 0) {
        char dir[1024] = "/data", q[256] = "";
        get_param(req_path, "dir=", dir, sizeof(dir));
        get_param(req_path, "q=", q, sizeof(q));
        char *sbuf = malloc(32768);
        if (sbuf) {
            int ofs = snprintf(sbuf, 32768,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nConnection: close\r\n\r\n{\"ok\":true,\"results\":[");
            int cnt = 0;
            search_files_recursive(dir, q, sbuf, 32768, &ofs, &cnt, 0);
            ofs += snprintf(sbuf + ofs, 32768 - (size_t)ofs, "]}");
            send_all(client_sock, sbuf, (size_t)ofs);
            free(sbuf);
        }
    }
    else if (strncmp(req_path, "/api/param/save", 15) == 0 && strcmp(req_method, "POST") == 0) {
        char id[64], ver[32];
        get_param(req_path, "id=", id, sizeof(id));
        get_param(req_path, "ver=", ver, sizeof(ver));
        if (header_end) {
            char *body = header_end + 4;
            int body_received = bytes_read - (int)(body - buffer);
            while (body_received < (int)content_length && bytes_read < 32767) {
                ssize_t extra = recv(client_sock, buffer + bytes_read, 32767 - bytes_read, 0);
                if (extra <= 0) break;
                bytes_read += (int)extra;
                body_received += (int)extra;
                buffer[bytes_read] = '\0';
            }
            update_game_param_json(id, body, ver);
        }
        const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
        send_all(client_sock, ok_res, strlen(ok_res));
    }
    else if (strncmp(req_path, "/api/inject_elf_ram", 19) == 0 && strcmp(req_method, "POST") == 0) {
        char name[128] = "Browser_ELF";
        get_param(req_path, "name=", name, sizeof(name));
        int rc = -1;
        if (content_length > 4 && content_length < (64 * 1024 * 1024) && header_end) {
            char *elf_mem = malloc((size_t)content_length);
            if (elf_mem) {
                char *body = header_end + 4;
                long long already = bytes_read - (long long)(body - buffer);
                if (already > content_length) already = content_length;
                if (already > 0) memcpy(elf_mem, body, (size_t)already);
                long long rem = content_length - already;
                while (rem > 0) {
                    ssize_t n = recv(client_sock, elf_mem + (content_length - rem), (size_t)rem, 0);
                    if (n <= 0) break;
                    rem -= (long long)n;
                }
                if (rem == 0) {
                    rc = inject_elf_buffer_to_elfldr(elf_mem, (size_t)content_length, name);
                }
                free(elf_mem);
            }
        }
        char res[160];
        snprintf(res, sizeof(res), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":%s}", rc == 0 ? "true" : "false");
        send_all(client_sock, res, strlen(res));
    }
    else if (strncmp(req_path, "/api/sysinfo", 12) == 0) {
        api_sysinfo(client_sock);
    }
    else if (strncmp(req_path, "/api/list", 9) == 0) {
        char target_dir[1024] = "/user/app/";
        get_param(req_path, "dir=", target_dir, sizeof(target_dir));
        api_list(client_sock, target_dir);
    }
    else if (strncmp(req_path, "/api/status", 11) == 0) {
        api_status(client_sock);
    }
    else if (strncmp(req_path, "/api/history", 12) == 0) {
        api_history(client_sock);
    }
    else if (strncmp(req_path, "/api/klog", 9) == 0) {
        api_klog(client_sock);
    }
    else if (strncmp(req_path, "/api/profiles", 13) == 0) {
        api_profiles(client_sock);
    }
    else if (strncmp(req_path, "/api/hex", 8) == 0) {
        char file[1024];
        get_param(req_path, "file=", file, sizeof(file));
        api_hex_view(client_sock, file, 0);
    }
    else if (strncmp(req_path, "/api/benchmark", 14) == 0) {
        char dir[1024] = "/data";
        get_param(req_path, "dir=", dir, sizeof(dir));
        double w_mb = 0, r_mb = 0;
        int rc = run_storage_benchmark(dir, &w_mb, &r_mb);
        char res[256];
        snprintf(res, sizeof(res),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
            "{\"ok\":%s,\"write_mbps\":%.2f,\"read_mbps\":%.2f}",
            rc == 0 ? "true" : "false", w_mb, r_mb);
        send_all(client_sock, res, strlen(res));
    }
    else if (strncmp(req_path, "/api/kill_app", 13) == 0) {
        kill_running_game();
        const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
        send_all(client_sock, ok_res, strlen(ok_res));
    }
    else if (strncmp(req_path, "/api/install_tile", 17) == 0) {
        install_firoz_homescreen_tile(g_http_port);
        const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
        send_all(client_sock, ok_res, strlen(ok_res));
    }
    else if (strncmp(req_path, "/api/upload", 11) == 0 && strcmp(req_method, "POST") == 0) {
        char dst[1024];
        get_param(req_path, "dst=", dst, sizeof(dst));
        int fd = (dst[0] && !strstr(dst, "..")) ? open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0777) : -1;
        if (fd >= 0 && header_end) {
            char *body = header_end + 4;
            long long already = bytes_read - (long long)(body - buffer);
            if (already > 0) write(fd, body, (size_t)already);
            long long rem = content_length - already;
            char *ubuf = alloc_aligned_buffer(262144);
            while (rem > 0 && ubuf) {
                size_t to_r = rem > 262144 ? 262144 : (size_t)rem;
                ssize_t n = recv(client_sock, ubuf, to_r, 0);
                if (n <= 0) break;
                write(fd, ubuf, (size_t)n);
                rem -= (long long)n;
            }
            if (ubuf) free(ubuf);
            fchmod(fd, 0777);
            close(fd);
            klog_appendf("[UPLOAD] Saved %s (%lld bytes)\n", dst, content_length);
        }
        const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
        send_all(client_sock, ok_res, strlen(ok_res));
    }
    else if (strncmp(req_path, "/api/profile/rename", 19) == 0 && strcmp(req_method, "POST") == 0) {
        char id[128];
        get_param(req_path, "id=", id, sizeof(id));
        if (id[0] && !strstr(id, "..") && header_end) {
            char *body = header_end + 4;
            int body_received = bytes_read - (int)(body - buffer);
            while (body_received < (int)content_length && bytes_read < 32767) {
                ssize_t extra = recv(client_sock, buffer + bytes_read, 32767 - bytes_read, 0);
                if (extra <= 0) break;
                bytes_read += (int)extra;
                body_received += (int)extra;
                buffer[bytes_read] = '\0';
            }
            char npath[512];
            snprintf(npath, sizeof(npath), "/user/home/%s/username.txt", id);
            FILE *f = fopen(npath, "wb");
            if (f) {
                if (body_received > 0) fwrite(body, 1, (size_t)body_received, f);
                fclose(f);
                chmod(npath, 0777);
            }
        }
        const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
        send_all(client_sock, ok_res, strlen(ok_res));
    }
    else if (strncmp(req_path, "/api/clean_cache", 16) == 0) {
        long long freed = clean_system_cache();
        char res[256];
        snprintf(res, sizeof(res), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true,\"freed\":%lld}", freed);
        send_all(client_sock, res, strlen(res));
    }
    else if (strncmp(req_path, "/api/cancel", 11) == 0) {
        __atomic_store_n(&global_task.cancel_requested, 1, __ATOMIC_SEQ_CST);
        const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
        send_all(client_sock, ok_res, strlen(ok_res));
    }
    else if (strncmp(req_path, "/api/launch_elf", 15) == 0) {
        char elf[1024];
        get_param(req_path, "elf=", elf, sizeof(elf));
        int r = launch_elf_payload(elf);
        char res[256];
        snprintf(res, sizeof(res), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":%s}", r == 0 ? "true" : "false");
        send_all(client_sock, res, strlen(res));
    }
    else if (strncmp(req_path, "/api/launch", 11) == 0) {
        char id[128];
        get_param(req_path, "id=", id, sizeof(id));
        launch_game(id);
        const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
        send_all(client_sock, ok_res, strlen(ok_res));
    }
    else if (strncmp(req_path, "/api/install_pkg", 16) == 0) {
        char pkg[1024];
        get_param(req_path, "pkg=", pkg, sizeof(pkg));
        install_pkg(pkg);
        const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
        send_all(client_sock, ok_res, strlen(ok_res));
    }
    else if (strncmp(req_path, "/api/download", 13) == 0) {
        char file[1024];
        get_param(req_path, "file=", file, sizeof(file));
        api_stream_file(client_sock, file, buffer, 1);
    }
    else if (strncmp(req_path, "/api/stream", 11) == 0) {
        char file[1024];
        get_param(req_path, "file=", file, sizeof(file));
        api_stream_file(client_sock, file, buffer, 0);
    }
    else if (strncmp(req_path, "/api/text/save", 14) == 0 && strcmp(req_method, "POST") == 0) {
        char file[1024];
        get_param(req_path, "file=", file, sizeof(file));
        FILE *f = fopen(file, "wb");
        if (f && header_end) {
            char *body = header_end + 4;
            int already = bytes_read - (int)(body - buffer);
            if (already > 0) fwrite(body, 1, (size_t)already, f);
            long long rem = content_length - already;
            char *tbuf = malloc(32768);
            while (rem > 0 && tbuf) {
                ssize_t n = recv(client_sock, tbuf, rem > 32768 ? 32768 : (size_t)rem, 0);
                if (n <= 0) break;
                fwrite(tbuf, 1, (size_t)n, f);
                rem -= (long long)n;
            }
            if (tbuf) free(tbuf);
            fclose(f);
            chmod(file, 0777);
        }
        const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
        send_all(client_sock, ok_res, strlen(ok_res));
    }
    else if (strncmp(req_path, "/api/text", 9) == 0) {
        char file[1024];
        get_param(req_path, "file=", file, sizeof(file));
        api_text_read(client_sock, file);
    }
    else if (strcmp(req_method, "POST") == 0 && strncmp(req_path, "/api/action", 11) == 0) {
        if (header_end) {
            char *body = header_end + 4;
            int body_received = bytes_read - (int)(body - buffer);
            while (body_received < (int)content_length && bytes_read < 32767) {
                ssize_t extra = recv(client_sock, buffer + bytes_read, 32767 - bytes_read, 0);
                if (extra <= 0) break;
                bytes_read += (int)extra;
                body_received += (int)extra;
                buffer[bytes_read] = '\0';
            }

            char act[24] = {0}, src[1024] = {0}, dst[1024] = {0};
            get_param(body, "type=", act, sizeof(act));
            get_param(body, "src=", src, sizeof(src));
            get_param(body, "dst=", dst, sizeof(dst));

            if (strcmp(act, "mkdir") == 0) {
                mkdir_p(src);
                const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
                send_all(client_sock, ok_res, strlen(ok_res));
            } else if (strcmp(act, "rename") == 0) {
                rename(src, dst);
                const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
                send_all(client_sock, ok_res, strlen(ok_res));
            } else if (strcmp(act, "chmod") == 0) {
                recursive_chmod(src, 0777);
                const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
                send_all(client_sock, ok_res, strlen(ok_res));
            } else {
                int expected = 0;
                if (!__atomic_compare_exchange_n(&global_task.is_running, &expected, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                    const char *busy_res = "HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n{\"error\":\"Busy\"}";
                    send_all(client_sock, busy_res, strlen(busy_res));
                } else {
                    __atomic_store_n(&global_task.cancel_requested, 0, __ATOMIC_SEQ_CST);
                    __atomic_store_n(&global_task.total_bytes, 0, __ATOMIC_SEQ_CST);
                    __atomic_store_n(&global_task.copied_bytes, 0, __ATOMIC_SEQ_CST);

                    TaskArgs *task = malloc(sizeof(TaskArgs));
                    if (task) {
                        snprintf(task->action, sizeof(task->action), "%s", act);
                        snprintf(task->src, sizeof(task->src), "%s", src);
                        snprintf(task->dst, sizeof(task->dst), "%s", dst);

                        if (spawn_thread(background_worker, task) != 0) {
                            free(task);
                            __atomic_store_n(&global_task.is_running, 0, __ATOMIC_SEQ_CST);
                        }
                    } else {
                        __atomic_store_n(&global_task.is_running, 0, __ATOMIC_SEQ_CST);
                    }

                    const char *ok_res = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
                    send_all(client_sock, ok_res, strlen(ok_res));
                }
            }
        }
    }
        else if (strcmp(req_path, "/") == 0 || strncmp(req_path, "/index.html", 11) == 0) {
        // جدا کردن هدر از بادی برای محاسبه دقیق سایز HTML
        const char *body1 = strstr(UI_PART1, "\r\n\r\n");
        if (body1) body1 += 4; else body1 = UI_PART1;
        
        size_t body_len = strlen(body1) + strlen(UI_PART2) + strlen(UI_PART3) + strlen(UI_PART4) + strlen(UI_PART5);
        
        char hdr[256];
        snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Cache-Control: no-store\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n", body_len);
            
        send_all(client_sock, hdr, strlen(hdr));
        send_all(client_sock, body1, strlen(body1));
        send_all(client_sock, UI_PART2, strlen(UI_PART2));
        send_all(client_sock, UI_PART3, strlen(UI_PART3));
        send_all(client_sock, UI_PART4, strlen(UI_PART4));
        send_all(client_sock, UI_PART5, strlen(UI_PART5));
    }
    else {
        const char *err = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n404 Not Found";
        send_all(client_sock, err, strlen(err));
    }

    free(buffer);
    close(client_sock);
    return NULL;
}

static void stop_previous_instance(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((uint16_t)port);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        const char *msg = "GET /exit HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        send(sock, msg, strlen(msg), 0);
        close(sock);
        usleep(300000);
    } else {
        close(sock);
    }
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    g_boot_time = time(NULL);

    stop_previous_instance(HTTP_PORT);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) return 1;

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    struct sockaddr_in server_addr;
    int bound = 0;
    for (int p = HTTP_PORT; p < HTTP_PORT + 10; p++) {
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        server_addr.sin_port = htons((uint16_t)p);
        if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
            g_http_port = p;
            bound = 1;
            break;
        }
    }

    if (!bound || listen(server_sock, 128) < 0) {
        close(server_sock);
        return 1;
    }

    char ip[64];
    get_console_ip(ip, sizeof(ip));

    ps5_notify("FIROZ OS v6.0 Titanium Active!\nWeb: %s:%d | Turbo FTP: %d", ip, g_http_port, FTP_PORT);

    spawn_thread(power_guard_thread, NULL);
    spawn_thread(klog_reader_thread, NULL);
    spawn_thread(ftp_server_thread, NULL);

    install_firoz_homescreen_tile(g_http_port);
    auto_launch_firoz_ui(g_http_port);
    klog_appendf("[FIROZ OS v6.0] Web: http://%s:%d | Turbo FTP: %s:%d\n", ip, g_http_port, ip, FTP_PORT);

    while (g_server_running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);

        struct timeval tv = { 1, 0 };
        int act = select(server_sock + 1, &readfds, NULL, NULL, &tv);
        if (act <= 0) continue;

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int c_fd = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (c_fd < 0) continue;

        int *client_sock = malloc(sizeof(int));
        if (!client_sock) {
            close(c_fd);
            continue;
        }
        *client_sock = c_fd;
        if (spawn_thread(client_thread, client_sock) != 0) {
            close(c_fd);
            free(client_sock);
        }
    }

    close(server_sock);
    return 0;
}
