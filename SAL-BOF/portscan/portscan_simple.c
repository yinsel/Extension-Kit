/*
 * AdaptixC2 - Simple Port Scanner BOF
 * 简化版端口扫描器，专注于稳定性和兼容性
 */

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "beacon.h"
#include "bofdefs.h"

// 扫描配置
#define DEFAULT_TIMEOUT     2000  // 减少超时时间从3秒到2秒
#define MAX_PORTS          200
#define MAX_CONCURRENT     10    // 最大并发扫描数
#define SCAN_BATCH_SIZE    8     // 增加批处理大小从5到8
#define BATCH_DELAY_MS     30    // 减少批次间延迟从50ms到30ms

// 端口定义 - 重新优化分类
// Level 1: Web和数据库端口 (快速扫描)
int g_level1_ports[] = {
    // Web服务
    80, 443, 8080, 8443,
    // 数据库服务
    1433, 1521, 3306, 5432, 6379, 27017,
    0
};

// Level 2: Web、数据库、Windows/Linux区分端口 (标准扫描)
int g_level2_ports[] = {
    // Web服务
    80, 443, 8080, 8443,
    // 数据库服务
    1433, 1521, 3306, 5432, 6379, 27017,
    // Windows特有服务
    135, 139, 445, 3389, 5985, 5986,
    // Linux特有服务
    22,
    // 基础设施服务
    21, 25, 53, 110, 143, 993, 995,
    0
};

// Level 3: 广泛的Web、数据库、域控、Linux等端口 (完整扫描)
int g_level3_ports[] = {
    // Web服务
    80, 443, 8080, 8443, 8000, 8888,
    // 数据库服务
    1433, 1521, 3306, 5432, 6379, 27017, 9200, 9300,
    // Windows/域控服务
    135, 139, 445, 3389, 5985, 5986, 88, 389, 636, 3268, 3269,
    // Linux/Unix服务
    22, 23,
    // 基础设施服务
    21, 25, 53, 69, 110, 111, 143, 993, 995,
    // 其他服务
    7, 9, 13, 19, 37, 79, 113, 119, 1025, 1434, 1604, 1723, 2000, 2001, 2048, 2049, 2100, 3128, 5000, 5060, 5061, 5900, 6000, 6667, 8081, 9000, 10000, 11211,
    0
};

void bofstart() {}
void bofstop() {}

// 简单的TCP端口扫描
int tcp_port_scan(const char* ip, int port, int timeout)
{
    SOCKET sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return 0;
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

    // 等待连接结果 - 优化select调用
    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(sock, &write_set);

    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    // 使用更高效的select调用，只监控写集合
    int result = WS2_32$select(sock + 1, NULL, &write_set, NULL, &tv);

    WS2_32$closesocket(sock);

    return (result > 0) ? 1 : 0;
}

// 获取端口服务名
const char* get_service_name(int port)
{
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 69: return "tftp";
        case 70: return "gopher";
        case 79: return "finger";
        case 80: return "http";
        case 88: return "kerberos";
        case 110: return "pop3";
        case 135: return "rpc";
        case 139: return "netbios";
        case 143: return "imap";
        case 443: return "https";
        case 445: return "smb";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1433: return "mssql";
        case 1521: return "oracle";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgres";
        case 5985: return "winrm";
        case 5986: return "winrm-ssl";
        case 6379: return "redis";
        case 8080: return "http-alt";
        case 8443: return "https-alt";
        case 27017: return "mongodb";
        default:
            if (port >= 70 && port <= 90) {
                return "custom";
            }
            return "unknown";
    }
}

// 解析单个IP地址
int parse_single_ip(const char* target, char* ip_str)
{
    MSVCRT$strcpy(ip_str, target);
    return 1;
}

// 简化的CIDR解析 - 只支持/24
int parse_cidr_simple(const char* cidr, char*** ip_list, int* count)
{
    char base_ip[16];
    char* slash = MSVCRT$strchr(cidr, '/');
    
    if (!slash) {
        return 0;
    }

    // 提取基础IP
    int ip_len = slash - cidr;
    if (ip_len >= 16) {
        return 0;
    }
    
    MSVCRT$memcpy(base_ip, cidr, ip_len);
    base_ip[ip_len] = '\0';

    // 简化：只支持/24网段
    int mask = 0;
    const char* mask_ptr = slash + 1;
    while (*mask_ptr >= '0' && *mask_ptr <= '9') {
        mask = mask * 10 + (*mask_ptr - '0');
        mask_ptr++;
    }

    if (mask != 24) {
        BeaconPrintf(CALLBACK_ERROR, "Only /24 CIDR notation supported in this version\n");
        return 0;
    }

    // 手动找到最后一个点
    char* last_dot = NULL;
    for (int i = 0; base_ip[i]; i++) {
        if (base_ip[i] == '.') {
            last_dot = &base_ip[i];
        }
    }
    if (!last_dot) {
        return 0;
    }

    int network_len = last_dot - base_ip + 1;
    
    // 分配254个IP（1-254）
    *count = 254;
    *ip_list = (char**)intAlloc(*count * sizeof(char*));
    if (!*ip_list) {
        return 0;
    }

    // 生成IP列表
    for (int i = 0; i < *count; i++) {
        (*ip_list)[i] = (char*)intAlloc(16 * sizeof(char));
        if (!(*ip_list)[i]) {
            break;
        }
        
        MSVCRT$memcpy((*ip_list)[i], base_ip, network_len);
        MSVCRT$sprintf((*ip_list)[i] + network_len, "%d", i + 1);
    }

    return 1;
}

// 解析自定义端口 - 支持逗号分隔和范围格式
int* parse_custom_ports(const char* port_spec, int* count)
{
    if (!port_spec || !port_spec[0]) {
        return NULL;
    }

    // 复制字符串用于解析
    char* spec_copy = (char*)intAlloc(MSVCRT$strlen(port_spec) + 1);
    if (!spec_copy) {
        return NULL;
    }
    MSVCRT$strcpy(spec_copy, port_spec);

    // 预处理：统计端口数量
    *count = 0;
    char* token = MSVCRT$strtok(spec_copy, ",");
    while (token) {
        // 跳过空格
        while (*token == ' ') token++;

        // 检查是否为范围格式
        char* dash = MSVCRT$strchr(token, '-');
        if (dash) {
            // 解析范围
            int start_port = 0, end_port = 0;

            // 解析起始端口
            char* ptr = token;
            while (*ptr >= '0' && *ptr <= '9') {
                start_port = start_port * 10 + (*ptr - '0');
                ptr++;
            }

            // 跳过 '-'
            ptr = dash + 1;

            // 解析结束端口
            while (*ptr >= '0' && *ptr <= '9') {
                end_port = end_port * 10 + (*ptr - '0');
                ptr++;
            }

            if (start_port > 0 && end_port > 0 && start_port <= end_port && end_port <= 65535) {
                int range_count = end_port - start_port + 1;
                if (range_count > 1000) { // 限制最大范围
                    range_count = 1000;
                }
                *count += range_count;
            }
        } else {
            // 单个端口
            int port = 0;
            char* ptr = token;
            while (*ptr >= '0' && *ptr <= '9') {
                port = port * 10 + (*ptr - '0');
                ptr++;
            }

            if (port > 0 && port <= 65535) {
                (*count)++;
            }
        }

        token = MSVCRT$strtok(NULL, ",");
    }

    if (*count == 0) {
        intFree(spec_copy);
        return NULL;
    }

    // 分配端口数组
    int* ports = (int*)intAlloc(*count * sizeof(int));
    if (!ports) {
        intFree(spec_copy);
        return NULL;
    }

    // 重新解析并填充端口数组
    MSVCRT$strcpy(spec_copy, port_spec);
    int port_index = 0;

    token = MSVCRT$strtok(spec_copy, ",");
    while (token && port_index < *count) {
        // 跳过空格
        while (*token == ' ') token++;

        // 检查是否为范围格式
        char* dash = MSVCRT$strchr(token, '-');
        if (dash) {
            // 解析范围
            int start_port = 0, end_port = 0;

            // 解析起始端口
            char* ptr = token;
            while (*ptr >= '0' && *ptr <= '9') {
                start_port = start_port * 10 + (*ptr - '0');
                ptr++;
            }

            // 跳过 '-'
            ptr = dash + 1;

            // 解析结束端口
            while (*ptr >= '0' && *ptr <= '9') {
                end_port = end_port * 10 + (*ptr - '0');
                ptr++;
            }

            if (start_port > 0 && end_port > 0 && start_port <= end_port && end_port <= 65535) {
                int range_count = end_port - start_port + 1;
                if (range_count > 1000) {
                    range_count = 1000;
                    end_port = start_port + 999;
                }

                for (int i = 0; i < range_count && port_index < *count; i++) {
                    ports[port_index++] = start_port + i;
                }
            }
        } else {
            // 单个端口
            int port = 0;
            char* ptr = token;
            while (*ptr >= '0' && *ptr <= '9') {
                port = port * 10 + (*ptr - '0');
                ptr++;
            }

            if (port > 0 && port <= 65535) {
                ports[port_index++] = port;
            }
        }

        token = MSVCRT$strtok(NULL, ",");
    }

    intFree(spec_copy);
    return ports;
}

// 主扫描函数
void simple_port_scan(const char* target, int scan_level, const char* custom_ports)
{
    char** ip_list = NULL;
    int ip_count = 0;
    int* ports = NULL;
    int port_count = 0;
    int free_ports = 0; // 标记是否需要释放端口数组

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting port scan for: %s\n", target);

    // 解析目标
    if (MSVCRT$strchr(target, '/')) {
        // CIDR格式
        if (!parse_cidr_simple(target, &ip_list, &ip_count)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to parse CIDR: %s\n", target);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %d hosts\n", ip_count);
    } else {
        // 单个IP
        ip_list = (char**)intAlloc(1 * sizeof(char*));
        ip_list[0] = (char*)intAlloc(16 * sizeof(char));
        MSVCRT$strcpy(ip_list[0], target);
        ip_count = 1;
    }

    // 选择端口
    if (scan_level == 0 && custom_ports && custom_ports[0]) {
        // 自定义端口
        ports = parse_custom_ports(custom_ports, &port_count);
        if (ports) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Using custom ports: %s (%d ports)\n", custom_ports, port_count);
            free_ports = 1;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Invalid custom port specification: %s\n", custom_ports);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Using default port list instead\n");
            scan_level = 2;
        }
    }

    if (scan_level > 0) {
        switch (scan_level) {
            case 1:
                ports = g_level1_ports;
                for (port_count = 0; g_level1_ports[port_count] != 0; port_count++);
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Level 1 scan: Web & Database ports (%d ports)\n", port_count);
                break;
            case 2:
                ports = g_level2_ports;
                for (port_count = 0; g_level2_ports[port_count] != 0; port_count++);
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Level 2 scan: Web, Database & OS-specific ports (%d ports)\n", port_count);
                break;
            case 3:
                ports = g_level3_ports;
                for (port_count = 0; g_level3_ports[port_count] != 0; port_count++);
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Level 3 scan: Comprehensive ports (%d ports)\n", port_count);
                break;
            default:
                ports = g_level2_ports;
                for (port_count = 0; g_level2_ports[port_count] != 0; port_count++);
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Default scan: Web, Database & OS-specific ports (%d ports)\n", port_count);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %d ports\n", port_count);

    // 并发扫描主机
    int total_open_ports = 0;
    for (int i = 0; i < ip_count; i++) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %s...\n", ip_list[i]);

        int host_open_ports = 0;

        // 分批并发扫描端口
        for (int batch_start = 0; batch_start < port_count; batch_start += SCAN_BATCH_SIZE) {
            int batch_end = batch_start + SCAN_BATCH_SIZE;
            if (batch_end > port_count) {
                batch_end = port_count;
            }

            // 并发扫描当前批次的端口
            for (int j = batch_start; j < batch_end; j++) {
                int port = ports[j];
                int state = tcp_port_scan(ip_list[i], port, DEFAULT_TIMEOUT);

                if (state > 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "  [+] Port %d (%s) - OPEN\n",
                               port, get_service_name(port));
                    host_open_ports++;
                    total_open_ports++;
                }
            }

            // 小延迟避免过快扫描
            if (batch_end < port_count) {
                KERNEL32$Sleep(BATCH_DELAY_MS); // 优化延迟时间
            }
        }

        if (host_open_ports > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Host %s: %d open ports found\n",
                       ip_list[i], host_open_ports);
        }

        // 进度报告
        if (ip_count > 10 && (i + 1) % 10 == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Progress: %d/%d hosts scanned\n", i + 1, ip_count);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Scan completed. Found %d open ports total.\n", total_open_ports);

    // 注意：Targets表集成需要在客户端实现
    // BOF输出结构化结果，客户端解析后添加到Targets表
    // 格式将在客户端代码中实现

    // 清理内存
    if (ip_list) {
        for (int i = 0; i < ip_count; i++) {
            if (ip_list[i]) {
                intFree(ip_list[i]);
            }
        }
        intFree(ip_list);
    }
    
    // 清理自定义端口数组
    if (free_ports && ports) {
        intFree(ports);
    }
}

// 主函数
int go(char* args, int len)
{
    char target[256] = {0};
    int scan_level = 2;
    char custom_ports[512] = {0};

    // 解析参数
    datap parser;
    BeaconDataParse(&parser, args, len);

    // 获取目标参数
    int target_size = 0;
    char* target_ptr = BeaconDataExtract(&parser, &target_size);
    if (target_ptr && target_size > 0) {
        MSVCRT$memcpy(target, target_ptr, target_size);
        target[target_size] = '\0';
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Usage: smartscan <target> [ports]\n");
        BeaconPrintf(CALLBACK_ERROR, "  target: IP address or CIDR (e.g., 192.168.1.1/24)\n");
        BeaconPrintf(CALLBACK_ERROR, "  ports:  1=fast, 2=normal (default), 3=full\n");
        return 0;
    }

    // 获取扫描级别参数（第二个参数）
    scan_level = BeaconDataInt(&parser);

    // 获取自定义端口参数（第三个参数）
    int ports_size = 0;
    char* ports_ptr = BeaconDataExtract(&parser, &ports_size);
    if (ports_ptr && ports_size > 0) {
        MSVCRT$memcpy(custom_ports, ports_ptr, ports_size);
        custom_ports[ports_size] = '\0';
    }


    // 执行扫描
    simple_port_scan(target, scan_level, custom_ports);

    return 0;
}