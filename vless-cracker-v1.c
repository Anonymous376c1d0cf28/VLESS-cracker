#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif

#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

#define MAX_STREAMS 1024
#define MAX_STREAM_BYTES 32768
#define MAX_REPLAY_RESPONSE_BYTES 65536
#define MAX_REPLAY_IGNORES 128
#define MAX_PROBED_SERVERS 4096
#define MAX_PROBE_BYTES 4096
#define REPLAY_TIMEOUT_MS 3000
#define DEFAULT_REPLAY_C_DELAY_SECONDS 1
#define STREAM_IDLE_SECONDS 30
#define PROBE_OBSERVE_TIMEOUT_MS 4000
#define TLS13_ENCRYPTED_ALERT_RECORD_LEN 19
#define DEFAULT_PROBE_FILE "characteristic.txt"
#define MAX_TLS_SNI 256
#define REQUIRED_CONFIRMATION_ROUNDS 3

typedef struct {
    int ip_version;
    uint8_t src[16];
    uint8_t dst[16];
    uint16_t sport;
    uint16_t dport;
} FlowKey;

typedef struct {
    FlowKey key;
    int used;
    int client_hello_printed;
    int expect_server_response;
    int server_response_printed;
    int replay_done;
    uint32_t start_seq;
    uint32_t next_seq;
    size_t len;
    uint8_t data[MAX_STREAM_BYTES];
    char sni[MAX_TLS_SNI];
    time_t last_seen;
} TcpStream;

typedef struct {
    int ip_version;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
} PacketInfo;

typedef struct {
    const uint8_t *record;
    size_t record_len;
} TlsRecordRef;

typedef struct {
    int used;
    FlowKey client_to_server;
    time_t expires_at;
} ReplayIgnore;

typedef struct {
    int used;
    int ip_version;
    uint8_t addr[16];
    uint16_t port;
    int in_progress;
    int excluded;
    unsigned int matched_rounds;
} ProbedServer;

typedef struct {
    uint8_t bytes[MAX_PROBE_BYTES];
    size_t len;
} ProbeSpec;

typedef struct {
    pcap_t *pcap;
    int datalink;
    char iface[IFNAMSIZ];
    unsigned int c_delay_seconds;
    ProbeSpec *probes;
    size_t probe_count;
    pthread_mutex_t lock;
    TcpStream streams[MAX_STREAMS];
    ReplayIgnore replay_ignores[MAX_REPLAY_IGNORES];
    ProbedServer probed_servers[MAX_PROBED_SERVERS];
} App;

typedef struct {
    App *app;
    FlowKey client_key;
    FlowKey server_key;
    unsigned int c_delay_seconds;
    size_t client_hello_len;
    uint8_t *client_hello;
    char sni[MAX_TLS_SNI];
    unsigned int round_no;
} ReplayTask;

typedef enum {
    REPLAY_STATUS_OK,
    REPLAY_STATUS_UNSUPPORTED_ADDRESS,
    REPLAY_STATUS_SOCKET_FAILED,
    REPLAY_STATUS_NONBLOCK_FAILED,
    REPLAY_STATUS_BIND_FAILED,
    REPLAY_STATUS_CONNECT_FAILED,
    REPLAY_STATUS_SEND_FAILED,
    REPLAY_STATUS_TIMEOUT,
    REPLAY_STATUS_SELECT_FAILED,
    REPLAY_STATUS_CLOSED,
    REPLAY_STATUS_RECV_FAILED,
    REPLAY_STATUS_BUFFER_FULL,
    REPLAY_STATUS_NO_RESPONSE
} ReplayStatus;

typedef enum {
    PROBE_STATUS_NONE,
    PROBE_STATUS_ALERT,
    PROBE_STATUS_FIN,
    PROBE_STATUS_RST,
    PROBE_STATUS_TIMEOUT
} ProbeStatus;

typedef struct {
    ProbeStatus status;
    int sent;
} AppDataCloseProbe;

typedef struct {
    AppDataCloseProbe appdata_close;
    int got_response;
    int connection_failed;
    ReplayStatus final_status;
} ReplayProbeResult;

typedef struct {
    ReplayTask *task;
    const uint8_t *client_hello;
    size_t client_hello_len;
    int attempt;
    size_t probe_index;
    ReplayProbeResult *result;
} ReplayProbeAttemptTask;

typedef enum {
    PROBE_ROUND_VALID,
    PROBE_ROUND_CONNECTION_ERROR,
    PROBE_ROUND_NO_SIGNAL,
    PROBE_ROUND_INTERNAL_ERROR
} ReplayRoundStatus;

static const char *replay_status_name(ReplayStatus status);

typedef enum {
    LOG_STANDARD,
    LOG_INFO,
    LOG_DEBUG
} LogLevel;

static volatile sig_atomic_t stop_capture = 0;
static LogLevel log_level = LOG_STANDARD;

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read_be24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void appendf(char *dst, size_t dst_len, const char *fmt, ...) {
    size_t used = strlen(dst);
    if (used >= dst_len) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dst + used, dst_len - used, fmt, ap);
    va_end(ap);
}

static int ipv6_is_link_local(const uint8_t *addr) {
    return addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80;
}

static void format_timeval(const struct timeval *ts, char *dst, size_t dst_len) {
    struct tm tmv;
    localtime_r(&ts->tv_sec, &tmv);
    strftime(dst, dst_len, "%Y-%m-%d %H:%M:%S", &tmv);
}

static void log_infof(const char *fmt, ...) {
    if (log_level < LOG_INFO) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static void log_debugf(const char *fmt, ...) {
    if (log_level < LOG_DEBUG) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static int loopback_family_to_ethertype(uint32_t family, uint16_t *ethertype) {
    if (family == AF_INET) {
        *ethertype = 0x0800;
        return 1;
    }

    if (family == AF_INET6) {
        *ethertype = 0x86dd;
        return 1;
    }

    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s -i <interface> [-f <bpf-filter>] [-l normal|info|debug|verbose] [-d c-delay-seconds]\n"
            "Default probe file: " DEFAULT_PROBE_FILE "\n"
            "\n"
            "Examples:\n"
            "  sudo %s -i eth0\n",
            argv0, argv0);
}

static int parse_log_level(const char *value) {
    if (strcmp(value, "normal") == 0 || strcmp(value, "quiet") == 0) {
        log_level = LOG_STANDARD;
        return 1;
    }
    if (strcmp(value, "info") == 0) {
        log_level = LOG_INFO;
        return 1;
    }
    if (strcmp(value, "debug") == 0 || strcmp(value, "verbose") == 0) {
        log_level = LOG_DEBUG;
        return 1;
    }
    return 0;
}

static int parse_uint_arg(const char *value, unsigned int min, unsigned int max,
                          unsigned int *out) {
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed < min || parsed > max) {
        return 0;
    }
    *out = (unsigned int)parsed;
    return 1;
}

static int hex_digit_value(int ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    ch = tolower((unsigned char)ch);
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    return -1;
}

static int is_hex_separator(int ch) {
    return isspace((unsigned char)ch) || ch == ':' || ch == '-';
}

static int parse_hex_bytes_arg(const char *value, uint8_t *out,
                               size_t out_cap, size_t *out_len) {
    int high = -1;
    size_t len = 0;

    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (is_hex_separator(*p)) {
            continue;
        }

        int digit = hex_digit_value(*p);
        if (digit < 0) {
            return 0;
        }

        if (high < 0) {
            high = digit;
            continue;
        }

        if (len >= out_cap) {
            return 0;
        }
        out[len++] = (uint8_t)((high << 4) | digit);
        high = -1;
    }

    if (high >= 0 || len == 0) {
        return 0;
    }

    *out_len = len;
    return 1;
}

static char *trim_ascii_whitespace(char *s) {
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }

    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    return s;
}

static int add_probe_spec(ProbeSpec **probes, size_t *count, size_t *cap,
                          const uint8_t *bytes, size_t len) {
    if (*count == *cap) {
        size_t new_cap = *cap ? *cap * 2 : 8;
        ProbeSpec *new_probes = realloc(*probes, new_cap * sizeof(*new_probes));
        if (!new_probes) {
            return 0;
        }
        *probes = new_probes;
        *cap = new_cap;
    }

    memcpy((*probes)[*count].bytes, bytes, len);
    (*probes)[*count].len = len;
    (*count)++;
    return 1;
}

static int load_probe_file(const char *path, ProbeSpec **probes,
                           size_t *count, size_t *cap) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "open probe file '%s': %s\n", path, strerror(errno));
        return 0;
    }

    char line[MAX_PROBE_BYTES * 3 + 16];
    unsigned int line_no = 0;
    while (fgets(line, sizeof(line), fp)) {
        line_no++;
        if (!strchr(line, '\n') && !feof(fp)) {
            fprintf(stderr, "probe file '%s' line %u is too long\n",
                    path, line_no);
            fclose(fp);
            return 0;
        }

        char *value = trim_ascii_whitespace(line);
        if (*value == '\0') {
            continue;
        }

        uint8_t bytes[MAX_PROBE_BYTES];
        size_t len = 0;
        if (!parse_hex_bytes_arg(value, bytes, sizeof(bytes), &len)) {
            fprintf(stderr, "invalid probe hex string in '%s' line %u: %s\n",
                    path, line_no, value);
            fclose(fp);
            return 0;
        }
        if (!add_probe_spec(probes, count, cap, bytes, len)) {
            fprintf(stderr, "append probe from '%s' line %u: %s\n",
                    path, line_no, strerror(errno));
            fclose(fp);
            return 0;
        }
    }

    if (ferror(fp)) {
        fprintf(stderr, "read probe file '%s': %s\n", path, strerror(errno));
        fclose(fp);
        return 0;
    }

    fclose(fp);
    return 1;
}

static void on_signal(int signo) {
    (void)signo;
    stop_capture = 1;
}

static int flow_equal(const FlowKey *a, const FlowKey *b) {
    return a->ip_version == b->ip_version &&
           a->sport == b->sport &&
           a->dport == b->dport &&
           memcmp(a->src, b->src, a->ip_version == 4 ? 4 : 16) == 0 &&
           memcmp(a->dst, b->dst, a->ip_version == 4 ? 4 : 16) == 0;
}

static uint32_t flow_hash(const FlowKey *key) {
    uint32_t h = 2166136261u;
    size_t n = key->ip_version == 4 ? 4 : 16;
    for (size_t i = 0; i < n; i++) {
        h ^= key->src[i];
        h *= 16777619u;
        h ^= key->dst[i];
        h *= 16777619u;
    }
    h ^= key->sport;
    h *= 16777619u;
    h ^= key->dport;
    return h;
}

static void reverse_flow_key(const FlowKey *in, FlowKey *out);
static void flow_addr_to_string(const FlowKey *key, int use_src, char *dst, size_t dst_len);

static TcpStream *get_stream(App *app, const FlowKey *key, time_t now) {
    uint32_t start = flow_hash(key) % MAX_STREAMS;
    int oldest = -1;
    time_t oldest_seen = now;

    for (uint32_t i = 0; i < MAX_STREAMS; i++) {
        uint32_t idx = (start + i) % MAX_STREAMS;
        TcpStream *s = &app->streams[idx];
        if (s->used && flow_equal(&s->key, key)) {
            s->last_seen = now;
            return s;
        }
        if (!s->used) {
            memset(s, 0, sizeof(*s));
            s->used = 1;
            s->key = *key;
            s->last_seen = now;
            return s;
        }
        if (now - s->last_seen > STREAM_IDLE_SECONDS) {
            memset(s, 0, sizeof(*s));
            s->used = 1;
            s->key = *key;
            s->last_seen = now;
            return s;
        }
        if (oldest < 0 || s->last_seen < oldest_seen) {
            oldest = (int)idx;
            oldest_seen = s->last_seen;
        }
    }

    TcpStream *s = &app->streams[oldest >= 0 ? oldest : 0];
    memset(s, 0, sizeof(*s));
    s->used = 1;
    s->key = *key;
    s->last_seen = now;
    return s;
}

static TcpStream *find_stream(App *app, const FlowKey *key) {
    uint32_t start = flow_hash(key) % MAX_STREAMS;
    for (uint32_t i = 0; i < MAX_STREAMS; i++) {
        uint32_t idx = (start + i) % MAX_STREAMS;
        TcpStream *s = &app->streams[idx];
        if (s->used && flow_equal(&s->key, key)) {
            return s;
        }
    }
    return NULL;
}

static void add_replay_ignore(App *app, const FlowKey *client_to_server, time_t now) {
    pthread_mutex_lock(&app->lock);
    int slot = -1;
    for (int i = 0; i < MAX_REPLAY_IGNORES; i++) {
        if (!app->replay_ignores[i].used || app->replay_ignores[i].expires_at <= now) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        slot = 0;
    }

    app->replay_ignores[slot].used = 1;
    app->replay_ignores[slot].client_to_server = *client_to_server;
    app->replay_ignores[slot].expires_at = now + 10;
    pthread_mutex_unlock(&app->lock);
}

static int should_ignore_replay_flow(App *app, const FlowKey *key, time_t now) {
    int result = 0;
    pthread_mutex_lock(&app->lock);
    for (int i = 0; i < MAX_REPLAY_IGNORES; i++) {
        ReplayIgnore *ignore = &app->replay_ignores[i];
        if (!ignore->used) {
            continue;
        }
        if (ignore->expires_at <= now) {
            ignore->used = 0;
            continue;
        }
        if (flow_equal(&ignore->client_to_server, key)) {
            result = 1;
            break;
        }

        FlowKey server_to_client;
        reverse_flow_key(&ignore->client_to_server, &server_to_client);
        if (flow_equal(&server_to_client, key)) {
            result = 1;
            break;
        }
    }
    pthread_mutex_unlock(&app->lock);
    return result;
}

static int server_address_equal(const ProbedServer *server, const FlowKey *server_key) {
    size_t addr_len = server_key->ip_version == 4 ? 4 : 16;
    return server->used &&
           server->ip_version == server_key->ip_version &&
           server->port == server_key->sport &&
           memcmp(server->addr, server_key->src, addr_len) == 0;
}

static int start_server_probe_round(App *app, const FlowKey *server_key,
                                    unsigned int *round_no) {
    int slot = -1;

    pthread_mutex_lock(&app->lock);
    for (int i = 0; i < MAX_PROBED_SERVERS; i++) {
        if (server_address_equal(&app->probed_servers[i], server_key)) {
            ProbedServer *server = &app->probed_servers[i];
            if (server->excluded || server->in_progress ||
                server->matched_rounds >= REQUIRED_CONFIRMATION_ROUNDS) {
                pthread_mutex_unlock(&app->lock);
                return 0;
            }
            server->in_progress = 1;
            *round_no = server->matched_rounds + 1;
            pthread_mutex_unlock(&app->lock);
            return 1;
        }
        if (slot < 0 && !app->probed_servers[i].used) {
            slot = i;
        }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&app->lock);
        return 0;
    }

    app->probed_servers[slot].used = 1;
    app->probed_servers[slot].ip_version = server_key->ip_version;
    app->probed_servers[slot].port = server_key->sport;
    app->probed_servers[slot].in_progress = 1;
    app->probed_servers[slot].excluded = 0;
    app->probed_servers[slot].matched_rounds = 0;
    memcpy(app->probed_servers[slot].addr, server_key->src,
           server_key->ip_version == 4 ? 4 : 16);
    *round_no = 1;
    pthread_mutex_unlock(&app->lock);
    return 1;
}

static void finish_server_probe_round(App *app, const FlowKey *server_key,
                                      int matched, int retry_later,
                                      unsigned int *matched_rounds_out,
                                      int *final_match_out) {
    *matched_rounds_out = 0;
    *final_match_out = 0;

    pthread_mutex_lock(&app->lock);
    for (int i = 0; i < MAX_PROBED_SERVERS; i++) {
        ProbedServer *server = &app->probed_servers[i];
        if (!server_address_equal(server, server_key)) {
            continue;
        }

        server->in_progress = 0;
        if (retry_later) {
            *matched_rounds_out = server->matched_rounds;
            break;
        }

        if (matched) {
            server->matched_rounds++;
            *matched_rounds_out = server->matched_rounds;
            if (server->matched_rounds >= REQUIRED_CONFIRMATION_ROUNDS) {
                *final_match_out = 1;
                server->excluded = 1;
            }
        } else {
            server->excluded = 1;
            *matched_rounds_out = server->matched_rounds;
        }
        break;
    }
    pthread_mutex_unlock(&app->lock);
}

static int seq_before(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) < 0;
}

static int seq_after(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) > 0;
}

static void append_stream(TcpStream *s, uint32_t seq, const uint8_t *payload, size_t len) {
    if (len == 0) {
        return;
    }
    if (s->server_response_printed || (s->client_hello_printed && !s->expect_server_response)) {
        return;
    }

    if (s->len == 0) {
        s->start_seq = seq;
        s->next_seq = seq;
    }

    if (seq == s->next_seq) {
        size_t room = MAX_STREAM_BYTES - s->len;
        size_t copy_len = len < room ? len : room;
        memcpy(s->data + s->len, payload, copy_len);
        s->len += copy_len;
        s->next_seq += (uint32_t)len;
        return;
    }

    if (seq_before(seq, s->start_seq)) {
        uint32_t seq_end = seq + (uint32_t)len;
        if (!seq_after(seq_end, s->start_seq)) {
            return;
        }

        size_t prefix_len = s->start_seq - seq;
        if (prefix_len > len) {
            return;
        }
        if (prefix_len > MAX_STREAM_BYTES - s->len) {
            s->len = 0;
            s->start_seq = seq;
            s->next_seq = seq;
            append_stream(s, seq, payload, len);
            return;
        }

        memmove(s->data + prefix_len, s->data, s->len);
        memcpy(s->data, payload, prefix_len);
        s->len += prefix_len;
        s->start_seq = seq;

        if (seq_after(seq_end, s->next_seq)) {
            size_t suffix_off = s->next_seq - seq;
            size_t suffix_len = len - suffix_off;
            size_t room = MAX_STREAM_BYTES - s->len;
            size_t copy_len = suffix_len < room ? suffix_len : room;
            memcpy(s->data + s->len, payload + suffix_off, copy_len);
            s->len += copy_len;
            s->next_seq = seq_end;
        }
        return;
    }

    if (seq_before(seq, s->next_seq)) {
        uint32_t overlap = s->next_seq - seq;
        if (overlap >= len) {
            return;
        }
        payload += overlap;
        len -= overlap;
        seq = s->next_seq;
        append_stream(s, seq, payload, len);
        return;
    }

    if (seq_after(seq, s->next_seq) && log_level >= LOG_DEBUG) {
        log_debugf("TCP stream gap detected expected_seq=%u got_seq=%u gap=%u; resetting stream buffer\n",
                     s->next_seq, seq, seq - s->next_seq);
    }
    s->len = 0;
    s->start_seq = seq;
    s->next_seq = seq;
    append_stream(s, seq, payload, len);
}

static void append_printable(char *dst, size_t dst_len, const uint8_t *src, size_t src_len) {
    size_t pos = strlen(dst);
    for (size_t i = 0; i < src_len && pos + 2 < dst_len; i++) {
        unsigned char c = src[i];
        dst[pos++] = isprint(c) ? (char)c : '.';
    }
    dst[pos] = '\0';
}

static void append_version_list(char *dst, size_t dst_len, const uint8_t *p, size_t len) {
    for (size_t i = 0; i + 1 < len; i += 2) {
        char tmp[16];
        snprintf(tmp, sizeof(tmp), "%s0x%02x%02x", dst[0] ? "," : "", p[i], p[i + 1]);
        strncat(dst, tmp, dst_len - strlen(dst) - 1);
    }
}

static void reverse_flow_key(const FlowKey *in, FlowKey *out) {
    memset(out, 0, sizeof(*out));
    out->ip_version = in->ip_version;
    memcpy(out->src, in->dst, in->ip_version == 4 ? 4 : 16);
    memcpy(out->dst, in->src, in->ip_version == 4 ? 4 : 16);
    out->sport = in->dport;
    out->dport = in->sport;
}

static int parse_extensions(const uint8_t *p, size_t len, char *sni, size_t sni_len,
                            char *alpn, size_t alpn_len,
                            char *versions, size_t versions_len) {
    size_t off = 0;
    int extension_count = 0;

    while (off + 4 <= len) {
        uint16_t type = read_be16(p + off);
        uint16_t ext_len = read_be16(p + off + 2);
        off += 4;
        if (off + ext_len > len) {
            return extension_count;
        }

        const uint8_t *ext = p + off;
        if (type == 0 && ext_len >= 5) {
            uint16_t list_len = read_be16(ext);
            size_t pos = 2;
            while (pos + 3 <= ext_len && pos < (size_t)list_len + 2) {
                uint8_t name_type = ext[pos];
                uint16_t name_len = read_be16(ext + pos + 1);
                pos += 3;
                if (pos + name_len > ext_len) {
                    break;
                }
                if (name_type == 0 && sni[0] == '\0') {
                    append_printable(sni, sni_len, ext + pos, name_len);
                    break;
                }
                pos += name_len;
            }
        } else if (type == 16 && ext_len >= 3) {
            uint16_t list_len = read_be16(ext);
            size_t pos = 2;
            while (pos + 1 <= ext_len && pos < (size_t)list_len + 2) {
                uint8_t name_len = ext[pos++];
                if (pos + name_len > ext_len) {
                    break;
                }
                if (alpn[0]) {
                    strncat(alpn, ",", alpn_len - strlen(alpn) - 1);
                }
                append_printable(alpn, alpn_len, ext + pos, name_len);
                pos += name_len;
            }
        } else if (type == 43 && ext_len >= 1) {
            uint8_t list_len = ext[0];
            if ((size_t)list_len + 1 <= ext_len) {
                append_version_list(versions, versions_len, ext + 1, list_len);
            }
        }

        off += ext_len;
        extension_count++;
    }

    return extension_count;
}

static int print_client_hello(const PacketInfo *info, const uint8_t *record,
                              size_t record_len, const struct timeval *ts,
                              char *sni_out, size_t sni_out_len) {
    if (record_len < 9 || record[0] != 0x16 || record[1] != 0x03 || record[5] != 0x01) {
        return 0;
    }

    uint16_t tls_record_len = read_be16(record + 3);
    uint32_t hs_len = read_be24(record + 6);
    if ((size_t)tls_record_len + 5 > record_len || hs_len + 9 > (size_t)tls_record_len + 5) {
        return 0;
    }

    const uint8_t *body = record + 9;
    size_t body_len = hs_len;
    if (body_len < 38) {
        return 0;
    }

    uint16_t legacy_version = read_be16(body);
    size_t off = 2 + 32;
    uint8_t session_id_len = body[off++];
    if (off + session_id_len + 2 > body_len) {
        return 0;
    }
    off += session_id_len;

    uint16_t cipher_len = read_be16(body + off);
    off += 2;
    if (off + cipher_len + 1 > body_len) {
        return 0;
    }
    off += cipher_len;

    uint8_t compression_len = body[off++];
    if (off + compression_len > body_len) {
        return 0;
    }
    off += compression_len;

    char sni[MAX_TLS_SNI] = "";
    char alpn[256] = "";
    char versions[128] = "";
    int extension_count = 0;

    if (off + 2 <= body_len) {
        uint16_t extensions_len = read_be16(body + off);
        off += 2;
        if (off + extensions_len <= body_len) {
            extension_count = parse_extensions(body + off, extensions_len,
                                               sni, sizeof(sni),
                                               alpn, sizeof(alpn),
                                               versions, sizeof(versions));
        }
    }

    if (sni_out && sni_out_len > 0) {
        snprintf(sni_out, sni_out_len, "%s", sni);
    }

    if (log_level == LOG_STANDARD) {
        return 1;
    }

    char timebuf[64];
    format_timeval(ts, timebuf, sizeof(timebuf));

    if (log_level == LOG_INFO) {
        printf("[%s.%06ld] TLS ClientHello %s:%u -> %s:%u",
               timebuf, (long)ts->tv_usec,
               info->src, info->sport, info->dst, info->dport);
        if (sni[0]) {
            printf(" sni=%s", sni);
        }
        if (alpn[0]) {
            printf(" alpn=%s", alpn);
        }
        if (versions[0]) {
            printf(" versions=%s", versions);
        }
        putchar('\n');
        fflush(stdout);
        return 1;
    }

    printf("[%s.%06ld] %s:%u -> %s:%u TLS ClientHello "
           "record_version=0x%02x%02x legacy_version=0x%04x "
           "cipher_suites=%u extensions=%d",
           timebuf, (long)ts->tv_usec,
           info->src, info->sport, info->dst, info->dport,
           record[1], record[2], legacy_version,
           cipher_len / 2, extension_count);

    if (sni[0]) {
        printf(" sni=%s", sni);
    }
    if (alpn[0]) {
        printf(" alpn=%s", alpn);
    }
    if (versions[0]) {
        printf(" supported_versions=%s", versions);
    }
    putchar('\n');
    fflush(stdout);
    return 1;
}

static int find_tls_handshake_record(const uint8_t *data, size_t len,
                                     uint8_t handshake_type, TlsRecordRef *ref) {
    for (size_t off = 0; off + 9 <= len; off++) {
        if (data[off] != 0x16 || data[off + 1] != 0x03) {
            continue;
        }
        uint16_t tls_len = read_be16(data + off + 3);
        if (tls_len < 4 || off + 5 + tls_len > len) {
            continue;
        }
        if (data[off + 5] != handshake_type) {
            continue;
        }
        ref->record = data + off;
        ref->record_len = 5 + tls_len;
        return 1;
    }
    return 0;
}

static int find_and_print_client_hello(const PacketInfo *info, const uint8_t *data,
                                       size_t len, const struct timeval *ts,
                                       char *sni_out, size_t sni_out_len) {
    TlsRecordRef ref;
    if (!find_tls_handshake_record(data, len, 0x01, &ref)) {
        return 0;
    }
    return print_client_hello(info, ref.record, ref.record_len, ts,
                              sni_out, sni_out_len);
}

static int server_hello_selected_version(const uint8_t *record, size_t record_len,
                                         uint16_t *version_out) {
    *version_out = 0;
    if (record_len < 9 || record[0] != 0x16 || record[1] != 0x03 || record[5] != 0x02) {
        return 0;
    }

    uint16_t tls_record_len = read_be16(record + 3);
    uint32_t hs_len = read_be24(record + 6);
    if ((size_t)tls_record_len + 5 > record_len ||
        hs_len + 9 > (size_t)tls_record_len + 5) {
        return 0;
    }

    const uint8_t *body = record + 9;
    size_t body_len = hs_len;
    if (body_len < 38) {
        return 0;
    }

    *version_out = read_be16(body);
    size_t off = 2 + 32;
    uint8_t session_id_len = body[off++];
    if (off + session_id_len + 3 > body_len) {
        return 0;
    }
    off += session_id_len;
    off += 2; /* cipher_suite */
    off += 1; /* legacy_compression_method */

    if (off + 2 > body_len) {
        return 1;
    }
    uint16_t extensions_len = read_be16(body + off);
    off += 2;
    if (off + extensions_len > body_len) {
        return 0;
    }

    size_t end = off + extensions_len;
    while (off + 4 <= end) {
        uint16_t type = read_be16(body + off);
        uint16_t ext_len = read_be16(body + off + 2);
        off += 4;
        if (off + ext_len > end) {
            return 0;
        }
        if (type == 43 && ext_len == 2) {
            *version_out = read_be16(body + off);
            return 1;
        }
        off += ext_len;
    }

    return 1;
}

static int find_server_hello_selected_version(const uint8_t *data, size_t len,
                                              uint16_t *version_out) {
    TlsRecordRef ref;
    if (!find_tls_handshake_record(data, len, 0x02, &ref)) {
        return 0;
    }
    return server_hello_selected_version(ref.record, ref.record_len, version_out);
}

static void fill_random_bytes(uint8_t *dst, size_t len) {
    size_t off = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        while (off < len) {
            ssize_t n = read(fd, dst + off, len - off);
            if (n > 0) {
                off += (size_t)n;
                continue;
            }
            if (n == -1 && errno == EINTR) {
                continue;
            }
            break;
        }
        close(fd);
    }

    uint32_t x = (uint32_t)time(NULL) ^ (uint32_t)getpid() ^ (uint32_t)(uintptr_t)dst;
    while (off < len) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        dst[off++] = (uint8_t)x;
    }
}

static uint32_t hash_bytes32(const uint8_t *value, size_t len) {
    if (len == 0) {
        return 0;
    }
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= value[i];
        hash *= 16777619u;
    }
    return hash;
}

static int randomize_client_hello_legacy_session_id(uint8_t *record, size_t record_len,
                                                    uint8_t *session_id_len_out,
                                                    uint32_t *before_hash_out,
                                                    uint32_t *after_hash_out) {
    *session_id_len_out = 0;
    *before_hash_out = 0;
    *after_hash_out = 0;
    if (record_len < 9 || record[0] != 0x16 || record[1] != 0x03 || record[5] != 0x01) {
        return 0;
    }

    uint16_t tls_record_len = read_be16(record + 3);
    uint32_t hs_len = read_be24(record + 6);
    if ((size_t)tls_record_len + 5 > record_len ||
        hs_len + 9 > (size_t)tls_record_len + 5) {
        return 0;
    }

    const size_t fixed_body_len = 2 + 32;
    uint8_t *body = record + 9;
    size_t body_len = hs_len;
    if (body_len < fixed_body_len + 1) {
        return 0;
    }

    size_t off = fixed_body_len;
    uint8_t session_id_len = body[off++];
    if (off + session_id_len > body_len) {
        return 0;
    }
    if (session_id_len == 0) {
        return 0;
    }

    *before_hash_out = hash_bytes32(body + off, session_id_len);
    fill_random_bytes(body + off, session_id_len);
    *after_hash_out = hash_bytes32(body + off, session_id_len);
    *session_id_len_out = session_id_len;
    return 1;
}

static const char *probe_status_name(ProbeStatus status) {
    switch (status) {
    case PROBE_STATUS_ALERT:
        return "ALERT";
    case PROBE_STATUS_FIN:
        return "FIN";
    case PROBE_STATUS_RST:
        return "RST";
    case PROBE_STATUS_TIMEOUT:
        return "TO";
    case PROBE_STATUS_NONE:
    default:
        return "NONE";
    }
}

static ProbeStatus replay_result_probe_status(const ReplayProbeResult *result) {
    if (!result->got_response ||
        result->appdata_close.status == PROBE_STATUS_NONE) {
        return PROBE_STATUS_NONE;
    }
    return result->appdata_close.status;
}

static int probe_rounds_match(const ReplayProbeResult *a,
                              const ReplayProbeResult *c,
                              size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (replay_result_probe_status(&a[i]) !=
            replay_result_probe_status(&c[i])) {
            return 0;
        }
    }
    return 1;
}

static char probe_comparison_code(const ReplayProbeResult *a,
                                  const ReplayProbeResult *c,
                                  size_t count) {
    return probe_rounds_match(a, c, count) ? 'E' : 'D';
}

static int probe_round_has_signal(const ReplayProbeResult *results,
                                  size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (replay_result_probe_status(&results[i]) != PROBE_STATUS_NONE) {
            return 1;
        }
    }
    return 0;
}

static void build_replay_probe_summary(const ReplayProbeResult *results,
                                       size_t count,
                                       const char *label,
                                       char *dst, size_t dst_len) {
    appendf(dst, dst_len, "%s{X=", label);
    for (size_t i = 0; i < count; i++) {
        if (i > 0) {
            appendf(dst, dst_len, ",");
        }
        appendf(dst, dst_len, "%s",
                probe_status_name(replay_result_probe_status(&results[i])));
    }
    appendf(dst, dst_len, "}");
}

static void build_comparison_summary(const ReplayProbeResult *a,
                                     const ReplayProbeResult *c,
                                     size_t count,
                                     char *dst, size_t dst_len) {
    char ac = probe_comparison_code(a, c, count);
    appendf(dst, dst_len, "cmp=X[%c]", ac);
}

static int report_filter_matches_a_fingerprint(const ReplayProbeResult *a,
                                               size_t count) {
    static const ProbeStatus expected[] = {
        PROBE_STATUS_TIMEOUT,
        PROBE_STATUS_ALERT,
        PROBE_STATUS_ALERT,
        PROBE_STATUS_ALERT,
        PROBE_STATUS_ALERT,
        PROBE_STATUS_ALERT,
        PROBE_STATUS_ALERT
    };

    if (count != sizeof(expected) / sizeof(expected[0])) {
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        if (replay_result_probe_status(&a[i]) != expected[i]) {
            return 0;
        }
    }
    return 1;
}

static int replay_probe_matches_alarm_condition(const ReplayProbeResult *a,
                                                const ReplayProbeResult *c,
                                                size_t probe_count) {
    return !probe_rounds_match(a, c, probe_count) &&
           report_filter_matches_a_fingerprint(a, probe_count);
}

static void print_replay_comparison(const FlowKey *client_key,
                                    const FlowKey *server_key,
                                    const char *sni,
                                    const ReplayProbeResult *a,
                                    const ReplayProbeResult *c,
                                    size_t probe_count) {
    struct timeval ts;
    gettimeofday(&ts, NULL);

    char timebuf[64];
    struct tm tmv;
    localtime_r(&ts.tv_sec, &tmv);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tmv);

    char server_addr[INET6_ADDRSTRLEN];
    flow_addr_to_string(server_key, 1, server_addr, sizeof(server_addr));
    char client_addr[INET6_ADDRSTRLEN];
    flow_addr_to_string(client_key, 1, client_addr, sizeof(client_addr));
    const char *sni_value = (sni && sni[0]) ? sni : "-";

    if (probe_count == 0) {
        return;
    }

    char result_summary[65536] = "";
    build_replay_probe_summary(a, probe_count, "A",
                               result_summary, sizeof(result_summary));
    appendf(result_summary, sizeof(result_summary), "|");
    build_replay_probe_summary(c, probe_count, "B",
                               result_summary, sizeof(result_summary));

    char comparison_summary[512] = "";
    build_comparison_summary(a, c, probe_count, comparison_summary,
                             sizeof(comparison_summary));

    int mismatch = !probe_rounds_match(a, c, probe_count);
    int alarm_condition = replay_probe_matches_alarm_condition(a, c,
                                                               probe_count);

    if (!mismatch) {
        log_infof("[%s.%06ld] TLS ReplayProbe MATCH server=%s:%u sni=%s probes=%zu %s result=%s\n",
                  timebuf, (long)ts.tv_usec, server_addr, server_key->sport,
                  sni_value, probe_count, comparison_summary, result_summary);
    } else if (!alarm_condition) {
        log_infof("[%s.%06ld] TLS ReplayProbe MISMATCH suppressed server=%s:%u sni=%s probes=%zu %s result=%s\n",
                  timebuf, (long)ts.tv_usec, server_addr, server_key->sport,
                  sni_value, probe_count, comparison_summary, result_summary);
    } else {
        printf("\033[31m[%s.%06ld] TLS ReplayProbe MISMATCH, VLESS/REALITY connection detected after %u/%u confirmations. client=%s:%u server=%s:%u sni=%s probes=%zu %s result=%s",
               timebuf, (long)ts.tv_usec,
               REQUIRED_CONFIRMATION_ROUNDS,
               REQUIRED_CONFIRMATION_ROUNDS,
               client_addr, client_key->sport,
               server_addr, server_key->sport,
               sni_value,
               probe_count,
               comparison_summary,
               result_summary);
        printf("\033[0m\n");
    }
    fflush(stdout);
}

static void flow_addr_to_string(const FlowKey *key, int use_src,
                                char *dst, size_t dst_len) {
    int family = key->ip_version == 4 ? AF_INET : AF_INET6;
    const uint8_t *addr = use_src ? key->src : key->dst;
    if (!inet_ntop(family, addr, dst, (socklen_t)dst_len)) {
        snprintf(dst, dst_len, "?");
    }
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int bind_socket_to_interface(int fd, int family, const char *iface) {
    if (!iface || iface[0] == '\0' || strcmp(iface, "any") == 0) {
        errno = ENODEV;
        return -1;
    }

#ifndef SO_BINDTODEVICE
#error "SO_BINDTODEVICE is required on Linux"
#endif

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface,
                   (socklen_t)(strlen(iface) + 1)) == -1) {
        return -1;
    }
    (void)family;
    return 0;
}

static int wait_fd(int fd, int for_write, int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int rc = select(fd + 1, for_write ? NULL : &fds, for_write ? &fds : NULL, NULL, &tv);
    if (rc <= 0) {
        return rc;
    }
    return FD_ISSET(fd, &fds) ? 1 : 0;
}

static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addr_len,
                                int timeout_ms) {
    int rc = connect(fd, addr, addr_len);
    if (rc == 0) {
        return 0;
    }
    if (errno != EINPROGRESS) {
        return -1;
    }

    rc = wait_fd(fd, 1, timeout_ms);
    if (rc <= 0) {
        errno = rc == 0 ? ETIMEDOUT : errno;
        return -1;
    }

    int err = 0;
    socklen_t err_len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) == -1) {
        return -1;
    }
    if (err != 0) {
        errno = err;
        return -1;
    }
    return 0;
}

static int send_all_with_timeout(int fd, const uint8_t *buf, size_t len, int timeout_ms) {
    size_t sent = 0;
    while (sent < len) {
        int rc = wait_fd(fd, 1, timeout_ms);
        if (rc <= 0) {
            errno = rc == 0 ? ETIMEDOUT : errno;
            return -1;
        }

#ifdef MSG_NOSIGNAL
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
#else
        ssize_t n = send(fd, buf + sent, len - sent, 0);
#endif
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            continue;
        }
        return -1;
    }
    return 0;
}

static int fill_sockaddr_from_server_key(const FlowKey *server_key,
                                         struct sockaddr_storage *storage,
                                         socklen_t *storage_len) {
    memset(storage, 0, sizeof(*storage));
    if (server_key->ip_version == 4) {
        struct sockaddr_in *addr = (struct sockaddr_in *)storage;
        addr->sin_family = AF_INET;
        addr->sin_port = htons(server_key->sport);
        memcpy(&addr->sin_addr, server_key->src, 4);
        *storage_len = sizeof(*addr);
        return AF_INET;
    }

    if (server_key->ip_version == 6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)storage;
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(server_key->sport);
        memcpy(&addr->sin6_addr, server_key->src, 16);
        *storage_len = sizeof(*addr);
        return AF_INET6;
    }

    return -1;
}

static const char *replay_status_name(ReplayStatus status) {
    switch (status) {
    case REPLAY_STATUS_OK:
        return "ok";
    case REPLAY_STATUS_UNSUPPORTED_ADDRESS:
        return "unsupported_address";
    case REPLAY_STATUS_SOCKET_FAILED:
        return "socket_failed";
    case REPLAY_STATUS_NONBLOCK_FAILED:
        return "nonblock_failed";
    case REPLAY_STATUS_BIND_FAILED:
        return "bind_failed";
    case REPLAY_STATUS_CONNECT_FAILED:
        return "connect_failed";
    case REPLAY_STATUS_SEND_FAILED:
        return "send_failed";
    case REPLAY_STATUS_TIMEOUT:
        return "timeout";
    case REPLAY_STATUS_SELECT_FAILED:
        return "select_failed";
    case REPLAY_STATUS_CLOSED:
        return "closed";
    case REPLAY_STATUS_RECV_FAILED:
        return "recv_failed";
    case REPLAY_STATUS_BUFFER_FULL:
        return "buffer_full";
    case REPLAY_STATUS_NO_RESPONSE:
        return "no_response";
    default:
        return "unknown";
    }
}

static int replay_status_is_connection_error(ReplayStatus status) {
    return status == REPLAY_STATUS_SOCKET_FAILED ||
           status == REPLAY_STATUS_NONBLOCK_FAILED ||
           status == REPLAY_STATUS_BIND_FAILED ||
           status == REPLAY_STATUS_CONNECT_FAILED;
}

static void add_replay_ignore_from_socket(App *app, const FlowKey *server_key, int fd) {
    struct sockaddr_storage local;
    socklen_t local_len = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0) {
        return;
    }

    FlowKey client_to_server;
    memset(&client_to_server, 0, sizeof(client_to_server));
    client_to_server.ip_version = server_key->ip_version;
    memcpy(client_to_server.dst, server_key->src, server_key->ip_version == 4 ? 4 : 16);
    client_to_server.dport = server_key->sport;

    if (server_key->ip_version == 4 && local.ss_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)&local;
        memcpy(client_to_server.src, &addr->sin_addr, 4);
        client_to_server.sport = ntohs(addr->sin_port);
    } else if (server_key->ip_version == 6 && local.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&local;
        memcpy(client_to_server.src, &addr->sin6_addr, 16);
        client_to_server.sport = ntohs(addr->sin6_port);
    } else {
        return;
    }

    add_replay_ignore(app, &client_to_server, time(NULL));
}

static void log_socket_failure(const char *operation, const char *label,
                               int attempt, const char *server_addr,
                               uint16_t port, ReplayStatus status,
                               const char *message) {
    if (label) {
        log_infof("%s attempt=%d name=%s server=%s:%u failed=%s error=%s\n",
                  operation, attempt, label, server_addr, port,
                  replay_status_name(status), message);
    } else {
        log_infof("%s attempt=%d server=%s:%u failed=%s error=%s\n",
                  operation, attempt, server_addr, port,
                  replay_status_name(status), message);
    }
}

static int connect_replay_socket(App *app, const FlowKey *server_key,
                                 const char *operation, const char *label,
                                 int attempt, ReplayStatus *status_out) {
    *status_out = REPLAY_STATUS_NO_RESPONSE;

    struct sockaddr_storage remote;
    socklen_t remote_len = 0;
    int family = fill_sockaddr_from_server_key(server_key, &remote, &remote_len);
    if (family == -1) {
        *status_out = REPLAY_STATUS_UNSUPPORTED_ADDRESS;
        return -1;
    }

    char server_addr[INET6_ADDRSTRLEN];
    flow_addr_to_string(server_key, 1, server_addr, sizeof(server_addr));
    if (label) {
        log_infof("%s attempt=%d name=%s server=%s:%u\n",
                  operation, attempt, label, server_addr, server_key->sport);
    } else {
        log_infof("%s attempt=%d server=%s:%u\n",
                  operation, attempt, server_addr, server_key->sport);
    }

    int fd = socket(family, SOCK_STREAM, 0);
    if (fd == -1) {
        *status_out = REPLAY_STATUS_SOCKET_FAILED;
        log_socket_failure(operation, label, attempt, server_addr,
                           server_key->sport, *status_out, strerror(errno));
        return -1;
    }

    if (set_nonblocking(fd) == -1) {
        *status_out = REPLAY_STATUS_NONBLOCK_FAILED;
        log_socket_failure(operation, label, attempt, server_addr,
                           server_key->sport, *status_out, strerror(errno));
        close(fd);
        return -1;
    }

    if (bind_socket_to_interface(fd, family, app->iface) == -1) {
        *status_out = REPLAY_STATUS_BIND_FAILED;
        if (label) {
            log_infof("%s bind interface failed iface=%s name=%s server=%s:%u error=%s\n",
                      operation, app->iface, label, server_addr,
                      server_key->sport, strerror(errno));
        } else {
            log_infof("%s bind interface failed iface=%s server=%s:%u error=%s\n",
                      operation, app->iface, server_addr, server_key->sport,
                      strerror(errno));
        }
        close(fd);
        return -1;
    }

    if (connect_with_timeout(fd, (struct sockaddr *)&remote, remote_len,
                             REPLAY_TIMEOUT_MS) == -1) {
        *status_out = REPLAY_STATUS_CONNECT_FAILED;
        log_socket_failure(operation, label, attempt, server_addr,
                           server_key->sport, *status_out, strerror(errno));
        close(fd);
        return -1;
    }

    add_replay_ignore_from_socket(app, server_key, fd);
    *status_out = REPLAY_STATUS_OK;
    return fd;
}

static long elapsed_ms_since(const struct timeval *started_at) {
    struct timeval now;
    gettimeofday(&now, NULL);
    long sec = (long)(now.tv_sec - started_at->tv_sec);
    long usec = (long)(now.tv_usec - started_at->tv_usec);
    return sec * 1000 + usec / 1000;
}

static int send_probe_bytes(int fd, const FlowKey *server_key,
                            const char *server_addr, int attempt,
                            size_t probe_index, const ProbeSpec *probe,
                            AppDataCloseProbe *appdata_close,
                            struct timeval *appdata_started_at,
                            ReplayStatus *status_out) {
    if (send_all_with_timeout(fd, probe->bytes, probe->len,
                              REPLAY_TIMEOUT_MS) == -1) {
        *status_out = REPLAY_STATUS_SEND_FAILED;
        log_infof("TLS replay attempt=%d probe=%zu server=%s:%u probe_send_failed bytes=%zu error=%s\n",
                  attempt, probe_index + 1, server_addr, server_key->sport,
                  probe->len, strerror(errno));
        return 0;
    }

    appdata_close->sent = 1;
    gettimeofday(appdata_started_at, NULL);
    log_infof("TLS replay attempt=%d probe=%zu server=%s:%u sent probe bytes=%zu\n",
              attempt, probe_index + 1, server_addr, server_key->sport,
              probe->len);
    return 1;
}

static int buffer_contains_record_from_tail(const uint8_t *data, size_t len,
                                            uint8_t record_type,
                                            uint16_t record_len) {
    size_t full_len = 5 + (size_t)record_len;
    if (len < full_len) {
        return 0;
    }

    for (size_t pos = len - full_len + 1; pos > 0; pos--) {
        size_t off = pos - 1;
        if (data[off] == record_type &&
            data[off + 1] == 0x03 &&
            data[off + 2] == 0x03 &&
            read_be16(data + off + 3) == record_len) {
            return 1;
        }
    }

    return 0;
}

static int replay_client_hello_to_server_once(App *app, const FlowKey *server_key,
                                              const uint8_t *client_hello_record,
                                              size_t client_hello_len, int attempt,
                                              size_t probe_index,
                                              const ProbeSpec *probe,
                                              AppDataCloseProbe *appdata_close,
                                              ReplayStatus *status_out) {
    ReplayStatus status = REPLAY_STATUS_NO_RESPONSE;
    memset(appdata_close, 0, sizeof(*appdata_close));
    if (status_out) {
        *status_out = status;
    }

    char server_addr[INET6_ADDRSTRLEN];
    flow_addr_to_string(server_key, 1, server_addr, sizeof(server_addr));
    int fd = connect_replay_socket(app, server_key, "TLS replay", NULL,
                                   attempt, &status);
    if (fd == -1) {
        if (status_out) {
            *status_out = status;
        }
        return 0;
    }

    if (send_all_with_timeout(fd, client_hello_record, client_hello_len,
                              REPLAY_TIMEOUT_MS) == -1) {
        status = REPLAY_STATUS_SEND_FAILED;
        log_infof("TLS replay attempt=%d server=%s:%u failed=%s error=%s\n",
                  attempt, server_addr, server_key->sport,
                  replay_status_name(status), strerror(errno));
        close(fd);
        if (status_out) {
            *status_out = status;
        }
        return 0;
    }

    uint8_t response[4096];
    uint8_t alert_data[MAX_REPLAY_RESPONSE_BYTES];
    uint8_t post_probe_data[MAX_REPLAY_RESPONSE_BYTES];
    size_t response_len = 0;
    size_t alert_data_len = 0;
    size_t post_probe_data_len = 0;
    int got_response = 0;
    struct timeval appdata_started_at;

    for (;;) {
        int timeout_ms = REPLAY_TIMEOUT_MS;
        if (appdata_close->sent) {
            long elapsed_ms = elapsed_ms_since(&appdata_started_at);
            if (elapsed_ms >= PROBE_OBSERVE_TIMEOUT_MS) {
                appdata_close->status = PROBE_STATUS_TIMEOUT;
                status = REPLAY_STATUS_OK;
                break;
            }
            timeout_ms = PROBE_OBSERVE_TIMEOUT_MS - (int)elapsed_ms;
        }

        int rc = wait_fd(fd, 0, timeout_ms);
        if (rc == 0) {
            if (appdata_close->sent) {
                appdata_close->status = PROBE_STATUS_TIMEOUT;
                status = REPLAY_STATUS_OK;
            } else {
                status = REPLAY_STATUS_TIMEOUT;
            }
            if (!got_response) {
                log_infof("TLS replay attempt=%d server=%s:%u failed=%s bytes=%zu\n",
                          attempt, server_addr, server_key->sport,
                          replay_status_name(status), response_len);
            }
            break;
        }
        if (rc == -1) {
            if (errno == EINTR) {
                continue;
            }
            status = REPLAY_STATUS_SELECT_FAILED;
            log_infof("TLS replay attempt=%d server=%s:%u failed=%s error=%s bytes=%zu\n",
                      attempt, server_addr, server_key->sport,
                      replay_status_name(status), strerror(errno),
                      response_len);
            break;
        }

        ssize_t n = recv(fd, response, sizeof(response), 0);
        if (n > 0) {
            response_len += (size_t)n;
            size_t room = sizeof(alert_data) - alert_data_len;
            size_t copy_len = (size_t)n < room ? (size_t)n : room;
            if (copy_len > 0) {
                memcpy(alert_data + alert_data_len, response, copy_len);
                alert_data_len += copy_len;
                if (buffer_contains_record_from_tail(alert_data, alert_data_len,
                                                     0x15, 2)) {
                    appdata_close->status = PROBE_STATUS_ALERT;
                    status = REPLAY_STATUS_OK;
                    break;
                }
            }
            if (appdata_close->sent) {
                room = sizeof(post_probe_data) - post_probe_data_len;
                copy_len = (size_t)n < room ? (size_t)n : room;
                if (copy_len > 0) {
                    memcpy(post_probe_data + post_probe_data_len, response,
                           copy_len);
                    post_probe_data_len += copy_len;
                    if (buffer_contains_record_from_tail(
                            post_probe_data, post_probe_data_len, 0x17,
                            TLS13_ENCRYPTED_ALERT_RECORD_LEN)) {
                        appdata_close->status = PROBE_STATUS_ALERT;
                        status = REPLAY_STATUS_OK;
                        break;
                    }
                }
            }
            if (!got_response) {
                got_response = 1;
                if (!send_probe_bytes(fd, server_key, server_addr, attempt,
                                      probe_index, probe,
                                      appdata_close, &appdata_started_at,
                                      &status)) {
                    break;
                }
            }
            if (response_len >= MAX_REPLAY_RESPONSE_BYTES) {
                status = REPLAY_STATUS_BUFFER_FULL;
                if (appdata_close->sent) {
                    appdata_close->status = PROBE_STATUS_TIMEOUT;
                }
                log_infof("TLS replay attempt=%d server=%s:%u failed=%s bytes=%zu\n",
                          attempt, server_addr, server_key->sport,
                          replay_status_name(status), response_len);
                break;
            }
            continue;
        }
        if (n == 0) {
            status = got_response ? REPLAY_STATUS_OK : REPLAY_STATUS_CLOSED;
            if (appdata_close->sent &&
                appdata_close->status == PROBE_STATUS_NONE) {
                appdata_close->status = PROBE_STATUS_FIN;
            }
            if (!got_response) {
                log_infof("TLS replay attempt=%d server=%s:%u failed=%s bytes=%zu\n",
                          attempt, server_addr, server_key->sport,
                          replay_status_name(status), response_len);
            }
            break;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            continue;
        }
        if (appdata_close->sent && errno == ECONNRESET) {
            appdata_close->status = PROBE_STATUS_RST;
            status = REPLAY_STATUS_OK;
            break;
        }
        status = REPLAY_STATUS_RECV_FAILED;
        if (appdata_close->sent) {
            appdata_close->status = PROBE_STATUS_TIMEOUT;
        }
        log_infof("TLS replay attempt=%d server=%s:%u failed=%s error=%s bytes=%zu\n",
                  attempt, server_addr, server_key->sport,
                  replay_status_name(status), strerror(errno),
                  response_len);
        break;
    }

    close(fd);
    if (got_response) {
        log_infof("TLS replay attempt=%d probe=%zu server=%s:%u complete probe_status=%s bytes=%zu\n",
                  attempt, probe_index + 1, server_addr, server_key->sport,
                  probe_status_name(appdata_close->status),
                  response_len);
    }
    if (status_out) {
        *status_out = status;
    }
    return got_response;
}

static void run_replay_probe_attempt(ReplayTask *task, const uint8_t *client_hello,
                                     size_t client_hello_len, int attempt,
                                     size_t probe_index,
                                     ReplayProbeResult *result) {
    memset(result, 0, sizeof(*result));
    result->final_status = REPLAY_STATUS_NO_RESPONSE;
    result->got_response = replay_client_hello_to_server_once(
        task->app, &task->server_key,
        client_hello, client_hello_len, attempt,
        probe_index, &task->app->probes[probe_index],
        &result->appdata_close, &result->final_status);
    result->connection_failed =
        replay_status_is_connection_error(result->final_status);
}

static void *replay_probe_attempt_worker(void *arg) {
    ReplayProbeAttemptTask *probe_task = (ReplayProbeAttemptTask *)arg;
    run_replay_probe_attempt(probe_task->task,
                             probe_task->client_hello,
                             probe_task->client_hello_len,
                             probe_task->attempt,
                             probe_task->probe_index,
                             probe_task->result);
    return NULL;
}

static ReplayRoundStatus run_replay_probe_round(ReplayTask *task,
                                                const uint8_t *client_hello,
                                                size_t client_hello_len,
                                                int attempt,
                                                ReplayProbeResult *results) {
    size_t probe_count = task->app->probe_count;
    if (probe_count == 0) {
        return PROBE_ROUND_VALID;
    }

    pthread_t *threads = calloc(probe_count, sizeof(*threads));
    ReplayProbeAttemptTask *probe_tasks = calloc(probe_count,
                                                 sizeof(*probe_tasks));
    int *created = calloc(probe_count, sizeof(*created));
    int round_valid = 1;
    int internal_error = 0;
    int connection_error = 0;
    int no_signal = 0;

    if (!threads || !probe_tasks || !created) {
        log_infof("TLS replay attempt=%d discarded; failed to allocate concurrent probe tasks\n",
                  attempt);
        free(threads);
        free(probe_tasks);
        free(created);
        return PROBE_ROUND_INTERNAL_ERROR;
    }

    for (size_t i = 0; i < probe_count; i++) {
        probe_tasks[i].task = task;
        probe_tasks[i].client_hello = client_hello;
        probe_tasks[i].client_hello_len = client_hello_len;
        probe_tasks[i].attempt = attempt;
        probe_tasks[i].probe_index = i;
        probe_tasks[i].result = &results[i];

        int rc = pthread_create(&threads[i], NULL,
                                replay_probe_attempt_worker,
                                &probe_tasks[i]);
        if (rc != 0) {
            log_infof("TLS replay attempt=%d discarded; failed to create probe thread probe=%zu error=%s\n",
                      attempt, i + 1, strerror(rc));
            round_valid = 0;
            internal_error = 1;
            break;
        }
        created[i] = 1;
    }

    for (size_t i = 0; i < probe_count; i++) {
        if (created[i]) {
            pthread_join(threads[i], NULL);
        }
    }

    if (round_valid) {
        for (size_t i = 0; i < probe_count; i++) {
            if (results[i].connection_failed) {
                log_infof("TLS replay attempt=%d discarded; connection failed probe=%zu status=%s\n",
                          attempt, i + 1,
                          replay_status_name(results[i].final_status));
                round_valid = 0;
                connection_error = 1;
                break;
            }
        }
    }

    if (round_valid && !probe_round_has_signal(results, probe_count)) {
        log_infof("TLS replay attempt=%d discarded; all probes returned NONE\n",
                  attempt);
        round_valid = 0;
        no_signal = 1;
    }

    free(threads);
    free(probe_tasks);
    free(created);
    if (internal_error) {
        return PROBE_ROUND_INTERNAL_ERROR;
    }
    if (round_valid) {
        return PROBE_ROUND_VALID;
    }

    if (connection_error) {
        return PROBE_ROUND_CONNECTION_ERROR;
    }
    if (no_signal) {
        return PROBE_ROUND_NO_SIGNAL;
    }
    return PROBE_ROUND_CONNECTION_ERROR;
}

static void *replay_probe_worker(void *arg) {
    ReplayTask *task = (ReplayTask *)arg;
    size_t probe_count = task->app->probe_count;
    ReplayProbeResult *a = calloc(probe_count, sizeof(*a));
    ReplayProbeResult *c = calloc(probe_count, sizeof(*c));
    unsigned int matched_rounds = 0;
    int final_match = 0;
    if (!a || !c) {
        finish_server_probe_round(task->app, &task->server_key, 0, 1,
                                  &matched_rounds, &final_match);
        free(a);
        free(c);
        free(task->client_hello);
        free(task);
        return NULL;
    }

    ReplayRoundStatus a_status = run_replay_probe_round(task,
                                                        task->client_hello,
                                                        task->client_hello_len,
                                                        1, a);
    ReplayRoundStatus b_status = PROBE_ROUND_INTERNAL_ERROR;

    uint8_t *c_client_hello = malloc(task->client_hello_len);
    if (!c_client_hello) {
        log_infof("TLS replay B skipped; failed to allocate ClientHello copy\n");
    } else {
        memcpy(c_client_hello, task->client_hello, task->client_hello_len);
        uint8_t session_id_len = 0;
        uint32_t session_id_before_hash = 0;
        uint32_t session_id_after_hash = 0;
        if (randomize_client_hello_legacy_session_id(c_client_hello,
                                                     task->client_hello_len,
                                                     &session_id_len,
                                                     &session_id_before_hash,
                                                     &session_id_after_hash)) {
            log_infof("TLS replay B randomized ClientHello legacy_session_id len=%u before=%08x after=%08x\n",
                      session_id_len, session_id_before_hash,
                      session_id_after_hash);
        } else {
            log_infof("TLS replay B skipped ClientHello legacy_session_id randomization; original length is zero or ClientHello parse failed\n");
        }

        log_infof("TLS replay waiting %us before attempt=B randomized session_id recheck\n",
                  task->c_delay_seconds);
        sleep(task->c_delay_seconds);
        b_status = run_replay_probe_round(task, c_client_hello,
                                          task->client_hello_len, 2, c);
    }
    free(c_client_hello);

    if (a_status != PROBE_ROUND_VALID ||
        b_status != PROBE_ROUND_VALID) {
        finish_server_probe_round(task->app, &task->server_key, 0, 1,
                                  &matched_rounds, &final_match);
        log_infof("TLS replay confirmation round=%u skipped; discarded round A=%s B=%s\n",
                  task->round_no,
                  a_status == PROBE_ROUND_VALID ? "valid" :
                  (a_status == PROBE_ROUND_NO_SIGNAL ? "no_signal" : "discarded"),
                  b_status == PROBE_ROUND_VALID ? "valid" :
                  (b_status == PROBE_ROUND_NO_SIGNAL ? "no_signal" : "discarded"));
    } else {
        int round_matches = replay_probe_matches_alarm_condition(a, c,
                                                                 probe_count);
        finish_server_probe_round(task->app, &task->server_key,
                                  round_matches, 0,
                                  &matched_rounds, &final_match);
        if (final_match) {
            print_replay_comparison(&task->client_key, &task->server_key,
                                    task->sni, a, c, probe_count);
        } else if (round_matches) {
            char server_addr[INET6_ADDRSTRLEN];
            flow_addr_to_string(&task->server_key, 1, server_addr,
                                sizeof(server_addr));
            log_infof("TLS replay confirmation round=%u/%u passed server=%s:%u\n",
                      matched_rounds, REQUIRED_CONFIRMATION_ROUNDS,
                      server_addr, task->server_key.sport);
        } else {
            char server_addr[INET6_ADDRSTRLEN];
            flow_addr_to_string(&task->server_key, 1, server_addr,
                                sizeof(server_addr));
            log_infof("TLS replay confirmation failed; excluding server=%s:%u round=%u\n",
                      server_addr, task->server_key.sport, task->round_no);
        }
    }
    free(a);
    free(c);
    free(task->client_hello);
    free(task);
    return NULL;
}

static void replay_client_hello_to_server(App *app, TcpStream *server_stream) {
    FlowKey client_key;
    reverse_flow_key(&server_stream->key, &client_key);
    TcpStream *client_stream = find_stream(app, &client_key);
    if (!client_stream) {
        return;
    }

    TlsRecordRef client_hello;
    if (!find_tls_handshake_record(client_stream->data, client_stream->len, 0x01, &client_hello)) {
        return;
    }

    unsigned int round_no = 0;
    if (!start_server_probe_round(app, &server_stream->key, &round_no)) {
        return;
    }

    ReplayTask *task = calloc(1, sizeof(*task));
    if (!task) {
        unsigned int matched_rounds = 0;
        int final_match = 0;
        finish_server_probe_round(app, &server_stream->key, 0, 1,
                                  &matched_rounds, &final_match);
        return;
    }

    task->client_hello = malloc(client_hello.record_len);
    if (!task->client_hello) {
        unsigned int matched_rounds = 0;
        int final_match = 0;
        finish_server_probe_round(app, &server_stream->key, 0, 1,
                                  &matched_rounds, &final_match);
        free(task);
        return;
    }

    task->app = app;
    task->client_key = client_key;
    task->server_key = server_stream->key;
    task->c_delay_seconds = app->c_delay_seconds;
    task->client_hello_len = client_hello.record_len;
    task->round_no = round_no;
    snprintf(task->sni, sizeof(task->sni), "%s", client_stream->sni);
    memcpy(task->client_hello, client_hello.record, client_hello.record_len);

    pthread_t thread;
    int rc = pthread_create(&thread, NULL, replay_probe_worker, task);
    if (rc != 0) {
        unsigned int matched_rounds = 0;
        int final_match = 0;
        finish_server_probe_round(app, &server_stream->key, 0, 1,
                                  &matched_rounds, &final_match);
        free(task->client_hello);
        free(task);
        return;
    }
    pthread_detach(thread);
}

static int skip_ipv6_extensions(const uint8_t *packet, size_t len, size_t *off, uint8_t *next) {
    while (*next == 0 || *next == 43 || *next == 44 || *next == 50 ||
           *next == 51 || *next == 60) {
        if (*off + 2 > len) {
            return 0;
        }
        if (*next == 44) {
            if (*off + 8 > len) {
                return 0;
            }
            uint16_t frag = read_be16(packet + *off + 2);
            if ((frag & 0xfff8) != 0) {
                return 0;
            }
            *next = packet[*off];
            *off += 8;
        } else if (*next == 51) {
            size_t ext_len = ((size_t)packet[*off + 1] + 2) * 4;
            *next = packet[*off];
            *off += ext_len;
        } else if (*next == 50) {
            return 0;
        } else {
            size_t ext_len = ((size_t)packet[*off + 1] + 1) * 8;
            *next = packet[*off];
            *off += ext_len;
        }
        if (*off > len) {
            return 0;
        }
    }
    return 1;
}

static int parse_ip_tcp(const uint8_t *packet, size_t len, uint16_t ethertype,
                        PacketInfo *info, FlowKey *key,
                        const uint8_t **payload, size_t *payload_len) {
    if (ethertype == 0x0800) {
        if (len < 20 || (packet[0] >> 4) != 4) {
            return 0;
        }
        size_t ihl = (packet[0] & 0x0f) * 4;
        if (ihl < 20 || len < ihl) {
            return 0;
        }
        uint16_t total_len = read_be16(packet + 2);
        if (total_len < ihl || total_len > len) {
            return 0;
        }
        uint16_t frag = read_be16(packet + 6);
        if ((frag & 0x1fff) != 0 || (frag & 0x2000) != 0) {
            return 0;
        }
        if (packet[9] != 6) {
            return 0;
        }
        const uint8_t *tcp = packet + ihl;
        size_t tcp_len = total_len - ihl;
        if (tcp_len < 20) {
            return 0;
        }
        size_t tcp_hlen = (tcp[12] >> 4) * 4;
        if (tcp_hlen < 20 || tcp_hlen > tcp_len) {
            return 0;
        }

        memset(info, 0, sizeof(*info));
        memset(key, 0, sizeof(*key));
        info->ip_version = key->ip_version = 4;
        memcpy(key->src, packet + 12, 4);
        memcpy(key->dst, packet + 16, 4);
        inet_ntop(AF_INET, packet + 12, info->src, sizeof(info->src));
        inet_ntop(AF_INET, packet + 16, info->dst, sizeof(info->dst));
        info->sport = key->sport = read_be16(tcp);
        info->dport = key->dport = read_be16(tcp + 2);
        info->seq = read_be32(tcp + 4);
        *payload = tcp + tcp_hlen;
        *payload_len = tcp_len - tcp_hlen;
        return *payload_len > 0;
    }

    if (ethertype == 0x86dd) {
        if (len < 40 || (packet[0] >> 4) != 6) {
            return 0;
        }
        size_t payload_total = read_be16(packet + 4);
        if (payload_total + 40 > len) {
            return 0;
        }
        if (ipv6_is_link_local(packet + 8) || ipv6_is_link_local(packet + 24)) {
            return 0;
        }
        uint8_t next = packet[6];
        size_t off = 40;
        if (!skip_ipv6_extensions(packet, 40 + payload_total, &off, &next) || next != 6) {
            return 0;
        }

        const uint8_t *tcp = packet + off;
        size_t tcp_len = 40 + payload_total - off;
        if (tcp_len < 20) {
            return 0;
        }
        size_t tcp_hlen = (tcp[12] >> 4) * 4;
        if (tcp_hlen < 20 || tcp_hlen > tcp_len) {
            return 0;
        }

        memset(info, 0, sizeof(*info));
        memset(key, 0, sizeof(*key));
        info->ip_version = key->ip_version = 6;
        memcpy(key->src, packet + 8, 16);
        memcpy(key->dst, packet + 24, 16);
        inet_ntop(AF_INET6, packet + 8, info->src, sizeof(info->src));
        inet_ntop(AF_INET6, packet + 24, info->dst, sizeof(info->dst));
        info->sport = key->sport = read_be16(tcp);
        info->dport = key->dport = read_be16(tcp + 2);
        info->seq = read_be32(tcp + 4);
        *payload = tcp + tcp_hlen;
        *payload_len = tcp_len - tcp_hlen;
        return *payload_len > 0;
    }

    return 0;
}

static int parse_link_packet(int datalink, const uint8_t *packet, size_t len,
                             const uint8_t **ip, size_t *ip_len, uint16_t *ethertype) {
    if (datalink == DLT_EN10MB) {
        if (len < 14) {
            return 0;
        }
        size_t off = 12;
        *ethertype = read_be16(packet + off);
        off += 2;
        while ((*ethertype == 0x8100 || *ethertype == 0x88a8 || *ethertype == 0x9100) &&
               off + 4 <= len) {
            *ethertype = read_be16(packet + off + 2);
            off += 4;
        }
        if (off > len) {
            return 0;
        }
        *ip = packet + off;
        *ip_len = len - off;
        return 1;
    }

    if (datalink == DLT_RAW) {
        if (len < 1) {
            return 0;
        }
        uint8_t version = packet[0] >> 4;
        *ethertype = version == 4 ? 0x0800 : version == 6 ? 0x86dd : 0;
        *ip = packet;
        *ip_len = len;
        return *ethertype != 0;
    }

    if (datalink == DLT_NULL) {
        if (len < 4) {
            return 0;
        }
        uint32_t family = 0;
        memcpy(&family, packet, sizeof(family));
        if (!loopback_family_to_ethertype(family, ethertype)) {
            return 0;
        }
        *ip = packet + 4;
        *ip_len = len - 4;
        return 1;
    }

    if (datalink == DLT_LINUX_SLL) {
        if (len < 16) {
            return 0;
        }
        *ethertype = read_be16(packet + 14);
        *ip = packet + 16;
        *ip_len = len - 16;
        return 1;
    }

    if (datalink == DLT_LINUX_SLL2) {
        if (len < 20) {
            return 0;
        }
        *ethertype = read_be16(packet);
        *ip = packet + 20;
        *ip_len = len - 20;
        return 1;
    }

    return 0;
}

static void expect_reverse_server_response(App *app, const FlowKey *client_key, time_t now) {
    FlowKey server_key;
    reverse_flow_key(client_key, &server_key);
    TcpStream *server_stream = get_stream(app, &server_key, now);
    server_stream->expect_server_response = 1;
    server_stream->server_response_printed = 0;

    char server_addr[INET6_ADDRSTRLEN];
    char client_addr[INET6_ADDRSTRLEN];
    flow_addr_to_string(&server_key, 1, server_addr, sizeof(server_addr));
    flow_addr_to_string(&server_key, 0, client_addr, sizeof(client_addr));
    log_debugf("TLS expecting server response %s:%u -> %s:%u\n",
                 server_addr, server_key.sport, client_addr, server_key.dport);
}

static void handle_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet) {
    App *app = (App *)user;
    if (stop_capture) {
        pcap_breakloop(app->pcap);
        return;
    }

    const uint8_t *ip = NULL;
    size_t ip_len = 0;
    uint16_t ethertype = 0;
    if (!parse_link_packet(app->datalink, packet, hdr->caplen, &ip, &ip_len, &ethertype)) {
        return;
    }

    PacketInfo info;
    FlowKey key;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    if (!parse_ip_tcp(ip, ip_len, ethertype, &info, &key, &payload, &payload_len)) {
        return;
    }

    if (should_ignore_replay_flow(app, &key, hdr->ts.tv_sec)) {
        return;
    }

    TcpStream *stream = get_stream(app, &key, hdr->ts.tv_sec);

    if (stream->expect_server_response && !stream->server_response_printed) {
        uint16_t server_hello_version = 0;
        if (!find_server_hello_selected_version(payload, payload_len,
                                                &server_hello_version)) {
            return;
        }
        stream->server_response_printed = 1;
        if (server_hello_version != 0x0304) {
            return;
        }
        log_infof("TLS ServerHello %s:%u -> %s:%u selected_version=0x%04x bytes=%zu\n",
                  info.src, info.sport, info.dst, info.dport,
                  server_hello_version, payload_len);
        if (!stream->replay_done) {
            stream->replay_done = 1;
            replay_client_hello_to_server(app, stream);
        }
        return;
    }

    append_stream(stream, info.seq, payload, payload_len);

    if (!stream->client_hello_printed &&
        find_and_print_client_hello(&info, stream->data, stream->len, &hdr->ts,
                                    stream->sni, sizeof(stream->sni))) {
        stream->client_hello_printed = 1;
        expect_reverse_server_response(app, &key, hdr->ts.tv_sec);
    }
}

int main(int argc, char **argv) {
    const char *iface = NULL;
    const char *filter = "tcp";
    unsigned int c_delay_seconds = DEFAULT_REPLAY_C_DELAY_SECONDS;
    ProbeSpec *probes = NULL;
    size_t probe_count = 0;
    size_t probe_cap = 0;
    int opt;

    while ((opt = getopt(argc, argv, "i:f:l:d:p:P:h")) != -1) {
        switch (opt) {
        case 'i':
            iface = optarg;
            break;
        case 'f':
            filter = optarg;
            break;
        case 'l':
            if (!parse_log_level(optarg)) {
                usage(argv[0]);
                return 1;
            }
            break;
        case 'd':
            if (!parse_uint_arg(optarg, 0, 86400, &c_delay_seconds)) {
                usage(argv[0]);
                return 1;
            }
            break;
        case 'p':
        {
            uint8_t bytes[MAX_PROBE_BYTES];
            size_t len = 0;
            if (!parse_hex_bytes_arg(optarg, bytes, sizeof(bytes), &len)) {
                fprintf(stderr, "invalid probe hex string: %s\n", optarg);
                usage(argv[0]);
                free(probes);
                return 1;
            }
            if (!add_probe_spec(&probes, &probe_count, &probe_cap,
                                bytes, len)) {
                fprintf(stderr, "append probe: %s\n", strerror(errno));
                free(probes);
                return 1;
            }
            break;
        }
        case 'P':
            if (!load_probe_file(optarg, &probes, &probe_count, &probe_cap)) {
                free(probes);
                return 1;
            }
            break;
        case 'h':
        default:
            usage(argv[0]);
            free(probes);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (probe_count == 0 &&
        !load_probe_file(DEFAULT_PROBE_FILE, &probes, &probe_count,
                         &probe_cap)) {
        free(probes);
        return 1;
    }

    if (!iface) {
        usage(argv[0]);
        free(probes);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(iface, 262144, 1, 1000, errbuf);
    if (!pcap) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", iface, errbuf);
        free(probes);
        return 1;
    }

    struct bpf_program bpf;
    if (pcap_compile(pcap, &bpf, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile('%s'): %s\n", filter, pcap_geterr(pcap));
        free(probes);
        pcap_close(pcap);
        return 1;
    }
    if (pcap_setfilter(pcap, &bpf) == -1) {
        fprintf(stderr, "pcap_setfilter('%s'): %s\n", filter, pcap_geterr(pcap));
        pcap_freecode(&bpf);
        free(probes);
        pcap_close(pcap);
        return 1;
    }
    pcap_freecode(&bpf);

    App *app = calloc(1, sizeof(*app));
    if (!app) {
        fprintf(stderr, "calloc(App): %s\n", strerror(errno));
        free(probes);
        pcap_close(pcap);
        return 1;
    }
    app->pcap = pcap;
    app->datalink = pcap_datalink(pcap);
    snprintf(app->iface, sizeof(app->iface), "%s", iface);
    app->c_delay_seconds = c_delay_seconds;
    app->probes = probes;
    app->probe_count = probe_count;
    if (pthread_mutex_init(&app->lock, NULL) != 0) {
        fprintf(stderr, "pthread_mutex_init failed\n");
        free(app->probes);
        free(app);
        pcap_close(pcap);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    int rc = pcap_loop(pcap, -1, handle_packet, (u_char *)app);
    if (rc == -1) {
        fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(pcap));
        rc = 1;
        goto cleanup_app;
    }

    rc = 0;

cleanup_app:
    pthread_mutex_destroy(&app->lock);
    free(app->probes);
    free(app);
    pcap_close(pcap);
    return rc;
}
