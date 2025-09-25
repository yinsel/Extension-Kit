/*
 * AdaptixC2 - Smart Port Scanner AxScript Command
 * 智能端口扫描器AxScript命令包装器
 */

var metadata = {
    name: "Smart Port Scanner",
    description: "智能端口扫描器，支持CIDR格式和自动Target Tabs集成"
};

var cmd_smartscan = ax.create_command("smartscan", "执行智能端口扫描", "smartscan 192.168.1.1 -p 80,443,22-25");
cmd_smartscan.addArgString("target", true, "目标IP地址或CIDR格式 (例如: 192.168.1.1 或 192.168.1.1/24)");
cmd_smartscan.addArgFlagString("-p", "ports", "端口范围: 1=快速, 2=标准, 3=完整, 或自定义端口 (例如: 80,443,22-25,3389)", "2");
cmd_smartscan.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = parsed_json["target"];
    let ports = parsed_json["ports"];

    // 验证端口参数
    let scan_level = 2; // 默认标准扫描
    let custom_ports = "";

    if (ports === "1" || ports === "2" || ports === "3") {
        // 预定义级别
        scan_level = parseInt(ports);
    } else if (ports && ports !== "2") {
        // 自定义端口列表
        custom_ports = ports;
        scan_level = 0; // 0表示自定义端口
    }

    // 准备BOF参数
    let bof_params = ax.bof_pack("cstr,int,cstr", [target, scan_level, custom_ports]);
    let bof_path = ax.script_dir() + "../_bin/portscan." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "智能端口扫描器 - 扫描目标: " + target);
});

// 注册命令组
var group_portscan = ax.create_commands_group("Port Scanner", [cmd_smartscan]);
ax.register_commands_group(group_portscan, ["beacon", "gopher"], ["windows"], []);