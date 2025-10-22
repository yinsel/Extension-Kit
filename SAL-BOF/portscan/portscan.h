/*
 * AdaptixC2 - Smart Port Scanner BOF Header
 * 智能端口扫描器头文件
 */

#ifndef PORTSCAN_H
#define PORTSCAN_H

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// 扫描类型定义
#define SCAN_TYPE_TCP 1
#define SCAN_TYPE_UDP 2

// 端口状态定义
#define PORT_CLOSED 0
#define PORT_OPEN   1
#define PORT_FILTERED 2

// 扫描作业结构
typedef struct {
    char ip[16];
    int* ports;
    int port_count;
    int scan_type;
    int timeout;
    int priority;
    ScanResult** results;
    int result_count;
    int max_results;
    HANDLE mutex;
} ScanJob;

// 端口定义结构
typedef struct {
    int port;
    int priority;
    const char* service;
    const char* category;
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

// 函数声明
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

#endif // PORTSCAN_H