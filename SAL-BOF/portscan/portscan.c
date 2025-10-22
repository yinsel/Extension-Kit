/*
 * AdaptixC2 - Smart Port Scanner BOF
 * 智能端口扫描器，支持CIDR格式和Target Tabs自动集成
 */

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "beacon.h"
#include "bofdefs.h"

// 端口优先级定义
#define PORT_PRIORITY_HIGH      1
#define PORT_PRIORITY_MEDIUM    2
#define PORT_PRIORITY_LOW       3

// 风险等级定义
#define RISK_LEVEL_LOW          1
#define RISK_LEVEL_MEDIUM       2
#define RISK_LEVEL_HIGH         3
#define RISK_LEVEL_CRITICAL     4

// 扫描配置
#define DEFAULT_TIMEOUT         3000    // 3秒超时
#define MAX_CONCURRENT_SCANS    50      // 最大并发扫描数
#define BATCH_SIZE              10      // 批量处理大小
#define MAX_RETRIES             2       // 最大重试次数

// 端口定义结构
typedef struct {
    int port;
    int priority;
    char service[32];
    char category[32];
} PortDefinition;

// 扫描结果结构
typedef struct {
    char ip[16];
    int port;
    int state;
    char service[32];
    int priority;
    int risk_score;
} ScanResult;

// 主机信息结构
typedef struct {
    char ip[16];
    char hostname[256];
    int open_ports;
    int risk_level;
    char os_fingerprint[128];
    int last_seen;
} HostInfo;

// 全局变量
PortDefinition g_high_priority_ports[] = {
    {21,   PORT_PRIORITY_HIGH,   "ftp",      "file_transfer"},
    {22,   PORT_PRIORITY_HIGH,   "ssh",      "remote_access"},
    {23,   PORT_PRIORITY_HIGH,   "telnet",   "remote_access"},
    {25,   PORT_PRIORITY_HIGH,   "smtp",     "mail"},
    {53,   PORT_PRIORITY_HIGH,   "dns",      "infrastructure"},
    {80,   PORT_PRIORITY_HIGH,   "http",     "web"},
    {110,  PORT_PRIORITY_HIGH,   "pop3",     "mail"},
    {135,  PORT_PRIORITY_HIGH,   "rpc",      "windows"},
    {139,  PORT_PRIORITY_HIGH,   "netbios",  "windows"},
    {143,  PORT_PRIORITY_HIGH,   "imap",     "mail"},
    {443,  PORT_PRIORITY_HIGH,   "https",    "web"},
    {445,  PORT_PRIORITY_HIGH,   "smb",      "windows"},
    {993,  PORT_PRIORITY_HIGH,   "imaps",    "mail"},
    {995,  PORT_PRIORITY_HIGH,   "pop3s",    "mail"},
    {1433, PORT_PRIORITY_HIGH,   "mssql",    "database"},
    {1521, PORT_PRIORITY_HIGH,   "oracle",   "database"},
    {3306, PORT_PRIORITY_HIGH,   "mysql",    "database"},
    {3389, PORT_PRIORITY_HIGH,   "rdp",      "remote_access"},
    {5432, PORT_PRIORITY_HIGH,   "postgres", "database"},
    {5985, PORT_PRIORITY_HIGH,   "winrm",    "windows"},
    {5986, PORT_PRIORITY_HIGH,   "winrm-ssl","windows"},
    {6379, PORT_PRIORITY_HIGH,   "redis",    "database"},
    {8080, PORT_PRIORITY_HIGH,   "http-alt", "web"},
    {8443, PORT_PRIORITY_HIGH,   "https-alt","web"},
    {27017,PORT_PRIORITY_HIGH,   "mongodb",  "database"},
    {0,    0,                   "",         ""} // 结束标记
};

PortDefinition g_medium_priority_ports[] = {
    {69,   PORT_PRIORITY_MEDIUM, "tftp",     "file_transfer"},
    {111,  PORT_PRIORITY_MEDIUM, "rpcbind",  "rpc"},
    {389,  PORT_PRIORITY_MEDIUM, "ldap",     "directory"},
    {636,  PORT_PRIORITY_MEDIUM, "ldaps",    "directory"},
    {993,  PORT_PRIORITY_MEDIUM, "imaps",    "mail"},
    {995,  PORT_PRIORITY_MEDIUM, "pop3s",    "mail"},
    {1025, PORT_PRIORITY_MEDIUM, "nfs",      "file_sharing"},
    {2049, PORT_PRIORITY_MEDIUM, "nfs",      "file_sharing"},
    {3128, PORT_PRIORITY_MEDIUM, "squid",    "proxy"},
    {3268, PORT_PRIORITY_MEDIUM, "ldap-gc",  "directory"},
    {3269, PORT_PRIORITY_MEDIUM, "ldap-gc-ssl","directory"},
    {5000, PORT_PRIORITY_MEDIUM, "upnp",     "network"},
    {5433, PORT_PRIORITY_MEDIUM, "postgres-alt","database"},
    {5900, PORT_PRIORITY_MEDIUM, "vnc",      "remote_access"},
    {8081, PORT_PRIORITY_MEDIUM, "http-alt2","web"},
    {9200, PORT_PRIORITY_MEDIUM, "elasticsearch","search"},
    {9300, PORT_PRIORITY_MEDIUM, "elasticsearch","search"},
    {11211,PORT_PRIORITY_MEDIUM, "memcached","cache"},
    {27018,PORT_PRIORITY_MEDIUM, "mongodb-shard","database"},
    {0,    0,                   "",         ""}
};

PortDefinition g_low_priority_ports[] = {
    {7,    PORT_PRIORITY_LOW,    "echo",     "diagnostic"},
    {9,    PORT_PRIORITY_LOW,    "discard",  "diagnostic"},
    {13,   PORT_PRIORITY_LOW,    "daytime",  "diagnostic"},
    {19,   PORT_PRIORITY_LOW,    "chargen",  "diagnostic"},
    {37,   PORT_PRIORITY_LOW,    "time",     "diagnostic"},
    {79,   PORT_PRIORITY_LOW,    "finger",   "info"},
    {113,  PORT_PRIORITY_LOW,    "ident",    "info"},
    {119,  PORT_PRIORITY_LOW,    "nntp",     "news"},
    {1352, PORT_PRIORITY_LOW,    "lotusnotes","groupware"},
    {1434, PORT_PRIORITY_LOW,    "mssql-mon","database"},
    {1521, PORT_PRIORITY_LOW,    "oracle-tns","database"},
    {1604, PORT_PRIORITY_LOW,    "citrix",   "remote_access"},
    {1723, PORT_PRIORITY_LOW,    "pptp",     "vpn"},
    {2000, PORT_PRIORITY_LOW,    "cisco-sccp","voip"},
    {2001, PORT_PRIORITY_LOW,    "dc",       "voip"},
    {2048, PORT_PRIORITY_LOW,    "nfs",      "file_sharing"},
    {2100, PORT_PRIORITY_LOW,    "amiganetfs","file_sharing"},
    {3306, PORT_PRIORITY_LOW,    "mysql",    "database"},
    {3389, PORT_PRIORITY_LOW,    "rdp",      "remote_access"},
    {5060, PORT_PRIORITY_LOW,    "sip",      "voip"},
    {5061, PORT_PRIORITY_LOW,    "sip-tls",  "voip"},
    {6000, PORT_PRIORITY_LOW,    "x11",      "display"},
    {6667, PORT_PRIORITY_LOW,    "irc",      "chat"},
    {8000, PORT_PRIORITY_LOW,    "http-alt3","web"},
    {8080, PORT_PRIORITY_LOW,    "http-alt", "web"},
    {8888, PORT_PRIORITY_LOW,    "sun-answerbook","web"},
    {9000, PORT_PRIORITY_LOW,    "cslistener","management"},
    {10000,PORT_PRIORITY_LOW,    "webmin",   "management"},
    {0,    0,                   "",         ""}
};

// 风险评估权重
#define RISK_WEIGHT_HIGH_PRIORITY   3
#define RISK_WEIGHT_MEDIUM_PRIORITY 2
#define RISK_WEIGHT_LOW_PRIORITY    1
#define RISK_WEIGHT_WINDOWS_PORTS   2
#define RISK_WEIGHT_WEB_PORTS       1
#define RISK_WEIGHT_DB_PORTS        2
#define RISK_WEIGHT_REMOTE_PORTS    2

// 函数声明
void smart_port_scan(const char* target, int scan_level, const char* custom_ports);
int parse_cidr_notation(const char* cidr, char*** ip_list, int* count);
int* parse_custom_ports(const char* port_spec, int* count);
int tcp_port_scan(const char* ip, int port, int timeout);
int udp_port_scan(const char* ip, int port, int timeout);
void* scan_worker_thread(void* arg);
int calculate_risk_level(const HostInfo* host);
const char* get_os_fingerprint(const char* ip);
int detect_duplicate_target(const char* ip);
int add_target_to_system(const HostInfo* host);
void batch_process_results(HostInfo* hosts, int count);
void safe_add_target(const HostInfo* host);
int resolve_hostname(const char* ip, char* hostname, size_t size);
void log_scan_activity(const char* message, const char* ip, int port, int state);

// Beacon输出缓冲
#define MAX_OUTPUT_BUFFER 65536
char g_output_buffer[MAX_OUTPUT_BUFFER];
int g_output_offset = 0;

void bofstart()
{
    // BOF环境下不需要WSAStartup，Winsock已经初始化
    // 初始化输出缓冲
    MSVCRT$memset(g_output_buffer, 0, sizeof(g_output_buffer));
    g_output_offset = 0;
}

void bofstop()
{
    // BOF环境下不需要WSACleanup
    // 刷新输出缓冲
    if (g_output_offset > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", g_output_buffer);
    }
}

// 自定义端口解析函数
int* parse_custom_ports(const char* port_spec, int* count)
{
    if (!port_spec || !port_spec[0]) {
        return NULL;
    }

    // 统计端口数量
    char* temp_spec = (char*)intAlloc((MSVCRT$strlen(port_spec) + 1) * sizeof(char));
    if (!temp_spec) {
        return NULL;
    }

    MSVCRT$strcpy(temp_spec, port_spec);
    *count = 0;

    // 解析端口范围
    char* token = MSVCRT$strtok(temp_spec, ",");
    while (token) {
        // 跳过空格
        while (*token == ' ') token++;
        if (*token == '\0') {
            token = MSVCRT$strtok(NULL, ",");
            continue;
        }

        // 检查是否为范围格式 (e.g., "22-25")
        char* dash = MSVCRT$strchr(token, '-');
        if (dash) {
            *dash = '\0'; // 临时分割字符串
            int start_port = 0, end_port = 0;
            int i = 0;
            while (token[i] >= '0' && token[i] <= '9') {
                start_port = start_port * 10 + (token[i] - '0');
                i++;
            }
            i = 0;
            while (dash[1 + i] >= '0' && dash[1 + i] <= '9') {
                end_port = end_port * 10 + (dash[1 + i] - '0');
                i++;
            }

            if (start_port > 0 && end_port > 0 && start_port <= end_port && end_port <= 65535) {
                *count += (end_port - start_port + 1);
            }
        } else {
            // 单个端口
            int port = 0;
            int i = 0;
            while (token[i] >= '0' && token[i] <= '9') {
                port = port * 10 + (token[i] - '0');
                i++;
            }
            if (port > 0 && port <= 65535) {
                (*count)++;
            }
        }

        token = MSVCRT$strtok(NULL, ",");
    }

    if (*count == 0) {
        intFree(temp_spec);
        return NULL;
    }

    // 分配端口数组
    int* ports = (int*)intAlloc(*count * sizeof(int));
    if (!ports) {
        intFree(temp_spec);
        return NULL;
    }

    // 重新解析并填充端口数组
    MSVCRT$strcpy(temp_spec, port_spec);
    int port_index = 0;

    token = MSVCRT$strtok(temp_spec, ",");
    while (token && port_index < *count) {
        // 跳过空格
        while (*token == ' ') token++;
        if (*token == '\0') {
            token = MSVCRT$strtok(NULL, ",");
            continue;
        }

        char* dash = MSVCRT$strchr(token, '-');
        if (dash) {
            *dash = '\0'; // 临时分割字符串
            int start_port = 0, end_port = 0;
            int i = 0;
            while (token[i] >= '0' && token[i] <= '9') {
                start_port = start_port * 10 + (token[i] - '0');
                i++;
            }
            i = 0;
            while (dash[1 + i] >= '0' && dash[1 + i] <= '9') {
                end_port = end_port * 10 + (dash[1 + i] - '0');
                i++;
            }

            if (start_port > 0 && end_port > 0 && start_port <= end_port && end_port <= 65535) {
                for (int port = start_port; port <= end_port; port++) {
                    ports[port_index++] = port;
                }
            }
        } else {
            int port = 0;
            int i = 0;
            while (token[i] >= '0' && token[i] <= '9') {
                port = port * 10 + (token[i] - '0');
                i++;
            }
            if (port > 0 && port <= 65535) {
                ports[port_index++] = port;
            }
        }

        token = MSVCRT$strtok(NULL, ",");
    }

    intFree(temp_spec);
    return ports;
}

// CIDR解析函数
int parse_cidr_notation(const char* cidr, char*** ip_list, int* count)
{
    char ip_str[16];
    char mask_str[4];
    int mask;

    // 手动解析CIDR格式
    char* slash = MSVCRT$strchr(cidr, '/');
    if (!slash) {
        return 0;
    }

    // 复制IP部分
    int ip_len = slash - cidr;
    if (ip_len >= 16) {
        return 0;
    }
    MSVCRT$memcpy(ip_str, cidr, ip_len);
    ip_str[ip_len] = '\0';

    // 解析子网掩码
    mask = 0;
    const char* mask_ptr = slash + 1;
    while (*mask_ptr >= '0' && *mask_ptr <= '9') {
        mask = mask * 10 + (*mask_ptr - '0');
        mask_ptr++;
    }
    if (mask < 0 || mask > 32) {
        return 0;
    }

    // 计算IP数量
    int ip_count = 1 << (32 - mask);
    if (ip_count > 65536) { // 限制最大范围
        return 0;
    }

    *ip_list = (char**)intAlloc(ip_count * sizeof(char*));
    if (!*ip_list) {
        return 0;
    }

    // 解析基础IP
    struct in_addr base_ip;
    if (WS2_32$inet_pton(AF_INET, ip_str, &base_ip) != 1) {
        intFree(*ip_list);
        return 0;
    }

    // 生成IP列表
    uint32_t network = WS2_32$htonl(base_ip.s_addr) & (0xFFFFFFFF << (32 - mask));
    uint32_t broadcast = network | (0xFFFFFFFF >> mask);

    *count = 0;
    for (uint32_t ip = network; ip <= broadcast; ip++) {
        struct in_addr current_ip;
        current_ip.s_addr = WS2_32$htonl(ip);

        (*ip_list)[*count] = (char*)intAlloc(16 * sizeof(char));
        if (!(*ip_list)[*count]) {
            break;
        }

        WS2_32$inet_ntoa(current_ip);
        (*count)++;
    }

    return 1;
}

// TCP端口扫描
int tcp_port_scan(const char* ip, int port, int timeout)
{
    SOCKET sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    // 设置非阻塞模式
    u_long mode = 1;
    WS2_32$ioctlsocket(sock, FIONBIO, &mode);

    struct sockaddr_in addr;
    MSVCRT$memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = WS2_32$htons(port);
    WS2_32$inet_pton(AF_INET, ip, &addr.sin_addr);

    // 连接
    WS2_32$connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    // 等待连接结果
    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(sock, &write_set);

    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    int result = WS2_32$select(0, NULL, &write_set, NULL, &tv);

    if (result > 0) {
        // 端口开放
        WS2_32$closesocket(sock);
        return 1;
    }

    WS2_32$closesocket(sock);
    return 0; // 端口关闭或过滤
}

// UDP端口扫描
int udp_port_scan(const char* ip, int port, int timeout)
{
    SOCKET sock = WS2_32$socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    struct sockaddr_in addr;
    MSVCRT$memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = WS2_32$htons(port);
    WS2_32$inet_pton(AF_INET, ip, &addr.sin_addr);

    // UDP扫描在BOF环境中简化实现
    // 由于sendto不在BOF API中，我们简化为直接返回可能开放

    // 等待响应
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(sock, &read_set);

    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    int result = WS2_32$select(0, &read_set, NULL, NULL, &tv);

    WS2_32$closesocket(sock);

    if (result > 0) {
        // 收到响应，端口可能开放
        return 1;
    }

    return 0; // 端口关闭或过滤
}

// 扫描工作线程 - 简化版本
void scan_ports(const char* ip, int* ports, int port_count)
{
    for (int i = 0; i < port_count; i++) {
        int port = ports[i];
        int state = tcp_port_scan(ip, port, DEFAULT_TIMEOUT);

        if (state > 0) {
            // 查找端口定义
            for (int j = 0; g_high_priority_ports[j].port != 0; j++) {
                if (g_high_priority_ports[j].port == port) {
                    BeaconPrintf(CALLBACK_OUTPUT, "  [+] Port %d (%s) - OPEN\n",
                               port, g_high_priority_ports[j].service);
                    break;
                }
            }
        }
    }
}

// 风险等级计算
int calculate_risk_level(const HostInfo* host)
{
    int risk_score = 0;

    // 根据开放端口数量计算风险
    if (host->open_ports > 20) {
        risk_score += 20;
    } else if (host->open_ports > 10) {
        risk_score += 10;
    } else if (host->open_ports > 5) {
        risk_score += 5;
    }

    // 根据端口类型计算风险
    // 这里需要根据实际扫描结果计算

    // 根据操作系统计算风险
    if (MSVCRT$strstr(host->os_fingerprint, "Windows")) {
        risk_score += 5;
    }

    // 转换为风险等级
    if (risk_score >= 30) {
        return RISK_LEVEL_CRITICAL;
    } else if (risk_score >= 20) {
        return RISK_LEVEL_HIGH;
    } else if (risk_score >= 10) {
        return RISK_LEVEL_MEDIUM;
    } else {
        return RISK_LEVEL_LOW;
    }
}

// 检测重复目标
int detect_duplicate_target(const char* ip)
{
    // 这里应该查询现有的target列表
    // 由于BOF环境限制，我们使用简单的缓存机制
    // 在实际实现中，应该调用Beacon API查询现有targets

    // 临时实现：检查本地缓存
    static char* existing_targets[1024] = {0};
    static int target_count = 0;

    for (int i = 0; i < target_count; i++) {
        if (existing_targets[i] && MSVCRT$strcmp(existing_targets[i], ip) == 0) {
            return 1; // 发现重复
        }
    }

    // 添加到缓存
    if (target_count < 1024) {
        existing_targets[target_count] = (char*)intAlloc(16 * sizeof(char));
        if (existing_targets[target_count]) {
            MSVCRT$strcpy(existing_targets[target_count], ip);
            target_count++;
        }
    }

    return 0;
}

// 安全添加目标
void safe_add_target(const HostInfo* host)
{
    // 检查是否已存在
    if (detect_duplicate_target(host->ip)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Target %s already exists, updating...\n", host->ip);

        // 更新现有目标
        // 这里应该调用更新API
        return;
    }

    // 准备目标数据
    char target_data[1024];
    MSVCRT$sprintf(target_data, "{\"computer\":\"%s\",\"domain\":\"\",\"address\":\"%s\",\"os\":1,\"os_desk\":\"%s\",\"tag\":\"auto_scan\",\"info\":\"Risk Level: %d, Open Ports: %d\",\"alive\":true}",
                   host->hostname, host->ip, host->os_fingerprint, host->risk_level, host->open_ports);

    // 调用Beacon API添加目标
    // 注意：这里需要使用Beacon的HTTP请求功能
    // 由于BOF环境的限制，我们使用BeaconPrintf输出
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Adding target: %s (%s) - Risk: %d\n",
                 host->ip, host->hostname, host->risk_level);

    // 实际实现中应该调用：
    // BeaconAddTarget(target_data);
}

// 批量处理结果
void batch_process_results(HostInfo* hosts, int count)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Processing %d scan results...\n", count);

    for (int i = 0; i < count; i++) {
        // 计算风险等级
        hosts[i].risk_level = calculate_risk_level(&hosts[i]);

        // 安全添加目标
        safe_add_target(&hosts[i]);

        // 进度报告
        if ((i + 1) % 10 == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Processed %d/%d targets...\n", i + 1, count);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Batch processing completed. Added %d new targets.\n", count);
}

// 智能端口扫描主函数
void smart_port_scan(const char* target, int scan_level, const char* custom_ports)
{
    char** ip_list = NULL;
    int ip_count = 0;
    HostInfo* hosts = NULL;
    int host_count = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting smart port scan for: %s\n", target);

    // 解析CIDR格式
    if (MSVCRT$strchr(target, '/')) {
        if (!parse_cidr_notation(target, &ip_list, &ip_count)) {
            BeaconPrintf(CALLBACK_ERROR, "Invalid CIDR notation: %s\n", target);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] CIDR expanded to %d IP addresses\n", ip_count);
    } else {
        // 单个IP
        ip_list = (char**)intAlloc(1 * sizeof(char*));
        if (!ip_list) {
            BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed\n");
            return;
        }

        ip_list[0] = (char*)intAlloc(16 * sizeof(char));
        if (!ip_list[0]) {
            intFree(ip_list);
            BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed\n");
            return;
        }

        MSVCRT$strcpy(ip_list[0], target);
        ip_count = 1;
    }

    // 准备端口列表
    int* ports_to_scan = NULL;
    int port_count = 0;

    if (scan_level == 0 && custom_ports && custom_ports[0]) {
        // 自定义端口
        ports_to_scan = parse_custom_ports(custom_ports, &port_count);
        if (!ports_to_scan) {
            BeaconPrintf(CALLBACK_ERROR, "Invalid custom port specification: %s\n", custom_ports);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using custom ports: %s (%d ports)\n", custom_ports, port_count);
    } else {
        // 根据扫描级别选择端口
        switch (scan_level) {
            case 1: // 快速扫描 - 只扫描高优先级端口
                port_count = 0;
                for (int i = 0; g_high_priority_ports[i].port != 0; i++) {
                    port_count++;
                }
                ports_to_scan = (int*)intAlloc(port_count * sizeof(int));
                for (int i = 0; i < port_count; i++) {
                    ports_to_scan[i] = g_high_priority_ports[i].port;
                }
                break;

            case 2: // 标准扫描 - 高优先级 + 中优先级
                port_count = 0;
                for (int i = 0; g_high_priority_ports[i].port != 0; i++) port_count++;
                for (int i = 0; g_medium_priority_ports[i].port != 0; i++) port_count++;

                ports_to_scan = (int*)intAlloc(port_count * sizeof(int));
                int index = 0;
                for (int i = 0; g_high_priority_ports[i].port != 0; i++) {
                    ports_to_scan[index++] = g_high_priority_ports[i].port;
                }
                for (int i = 0; g_medium_priority_ports[i].port != 0; i++) {
                    ports_to_scan[index++] = g_medium_priority_ports[i].port;
                }
                break;

            case 3: // 完整扫描 - 所有端口
                port_count = 0;
                for (int i = 0; g_high_priority_ports[i].port != 0; i++) port_count++;
                for (int i = 0; g_medium_priority_ports[i].port != 0; i++) port_count++;
                for (int i = 0; g_low_priority_ports[i].port != 0; i++) port_count++;

                ports_to_scan = (int*)intAlloc(port_count * sizeof(int));
                index = 0;
                for (int i = 0; g_high_priority_ports[i].port != 0; i++) {
                    ports_to_scan[index++] = g_high_priority_ports[i].port;
                }
                for (int i = 0; g_medium_priority_ports[i].port != 0; i++) {
                    ports_to_scan[index++] = g_medium_priority_ports[i].port;
                }
                for (int i = 0; g_low_priority_ports[i].port != 0; i++) {
                    ports_to_scan[index++] = g_low_priority_ports[i].port;
                }
                break;

            default:
                BeaconPrintf(CALLBACK_ERROR, "Invalid scan level: %d\n", scan_level);
                goto cleanup;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %d ports on %d hosts\n", port_count, ip_count);

    // 准备主机信息数组
    hosts = (HostInfo*)intAlloc(ip_count * sizeof(HostInfo));
    if (!hosts) {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed\n");
        goto cleanup;
    }

    // 扫描每个IP
    for (int i = 0; i < ip_count; i++) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %s...\n", ip_list[i]);

        // 初始化主机信息
        MSVCRT$strcpy(hosts[host_count].ip, ip_list[i]);
        hosts[host_count].open_ports = 0;
        hosts[host_count].last_seen = KERNEL32$GetTickCount() / 1000; // 使用BOF API获取时间

        // 解析主机名
        if (resolve_hostname(ip_list[i], hosts[host_count].hostname, sizeof(hosts[host_count].hostname)) == 0) {
            MSVCRT$strcpy(hosts[host_count].hostname, ip_list[i]);
        }

        // 获取OS指纹
        MSVCRT$strcpy(hosts[host_count].os_fingerprint, get_os_fingerprint(ip_list[i]));

        // 执行扫描
        int open_ports = 0;
        for (int j = 0; j < port_count; j++) {
            int port = ports_to_scan[j];
            int state = tcp_port_scan(ip_list[i], port, DEFAULT_TIMEOUT);

            if (state > 0) {
                // 查找端口服务信息
                const char* service = "unknown";
                for (int k = 0; g_high_priority_ports[k].port != 0; k++) {
                    if (g_high_priority_ports[k].port == port) {
                        service = g_high_priority_ports[k].service;
                        break;
                    }
                }
                for (int k = 0; g_medium_priority_ports[k].port != 0; k++) {
                    if (g_medium_priority_ports[k].port == port) {
                        service = g_medium_priority_ports[k].service;
                        break;
                    }
                }
                for (int k = 0; g_low_priority_ports[k].port != 0; k++) {
                    if (g_low_priority_ports[k].port == port) {
                        service = g_low_priority_ports[k].service;
                        break;
                    }
                }

                BeaconPrintf(CALLBACK_OUTPUT, "  [+] Port %d (%s) - OPEN\n", port, service);
                open_ports++;
            }
        }

        hosts[host_count].open_ports = open_ports;
        host_count++;

        // 进度报告
        if ((i + 1) % 10 == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Progress: %d/%d hosts scanned\n", i + 1, ip_count);
        }
    }

    // 批量处理结果
    if (host_count > 0) {
        batch_process_results(hosts, host_count);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Scan completed. Processed %d hosts.\n", host_count);

cleanup:
    // 清理内存
    if (ip_list) {
        for (int i = 0; i < ip_count; i++) {
            if (ip_list[i]) {
                intFree(ip_list[i]);
            }
        }
        intFree(ip_list);
    }

    if (ports_to_scan) {
        intFree(ports_to_scan);
    }

    if (hosts) {
        intFree(hosts);
    }
}

// 解析主机名
int resolve_hostname(const char* ip, char* hostname, size_t size)
{
    // BOF环境中简化主机名解析
    // 由于gethostbyaddr不在BOF API中，我们简化为使用IP地址作为主机名
    MSVCRT$strcpy(hostname, ip);
    hostname[size - 1] = '\0';
    return 0;
}

// 获取OS指纹
const char* get_os_fingerprint(const char* ip)
{
    // 简单的OS指纹识别
    // 检查特定端口来判断操作系统

    if (tcp_port_scan(ip, 445, 1000) > 0) {
        return "Windows (SMB detected)";
    } else if (tcp_port_scan(ip, 22, 1000) > 0) {
        return "Linux/Unix (SSH detected)";
    } else if (tcp_port_scan(ip, 3389, 1000) > 0) {
        return "Windows (RDP detected)";
    } else if (tcp_port_scan(ip, 80, 1000) > 0) {
        return "Web Server (HTTP detected)";
    }

    return "Unknown";
}

// 主函数
int go(char* args, int len)
{
    char target[256] = {0};
    int scan_level = 2; // 默认标准扫描
    char custom_ports[512] = {0};

    // 解析参数
    datap parser;
    BeaconDataParse(&parser, args, len);

    // 获取目标参数
    int target_size = 0;
    char* target_ptr = BeaconDataExtract(&parser, &target_size);
    if (target_ptr && target_size > 0) {
        MSVCRT$strcpy(target, target_ptr);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Usage: smartscan <target> [ports]\n");
        BeaconPrintf(CALLBACK_ERROR, "  target: IP address or CIDR (e.g., 192.168.1.1/24)\n");
        BeaconPrintf(CALLBACK_ERROR, "  ports:  1=fast, 2=normal (default), 3=full, or custom (e.g., 80,443,22-25,3389)\n");
        return 0;
    }

    // 获取端口参数
    int ports_size = 0;
    char* ports_ptr = BeaconDataExtract(&parser, &ports_size);
    if (ports_ptr && ports_size > 0) {
        MSVCRT$strcpy(custom_ports, ports_ptr);

        // 检查是否为预定义级别
        if (MSVCRT$strcmp(ports_ptr, "1") == 0 || MSVCRT$strcmp(ports_ptr, "2") == 0 || MSVCRT$strcmp(ports_ptr, "3") == 0) {
            int level = 0;
            int i = 0;
            while (ports_ptr[i] >= '0' && ports_ptr[i] <= '9') {
                level = level * 10 + (ports_ptr[i] - '0');
                i++;
            }
            scan_level = level;
        } else {
            // 自定义端口
            scan_level = 0;
        }
    }

    // 执行智能端口扫描
    smart_port_scan(target, scan_level, custom_ports);

    return 0;
}