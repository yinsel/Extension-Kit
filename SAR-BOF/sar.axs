var metadata = {
    name: "SAR-BOF",
    description: "Situation Awareness Remote BOFs"
};


var cmd_quser = ax.create_command("quser", "Query user sessions on a remote machine, providing session information", "quser MainDC");
cmd_quser.addArgString("host", "", "localhost");
cmd_quser.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let host = parsed_json["host"];

    let bof_params = ax.bof_pack("cstr", [host]);
    let bof_path = ax.script_dir() + "_bin/quser." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: quser");
});


var cmd_taskhound = ax.create_command("taskhound", 
    "Collect scheduled tasks from remote systems", 
    "taskhound 192.168.1.100 -u domain\\admin -p password -save C:\\Output -unsaved-creds -grab-blobs");

cmd_taskhound.addArgString("target", true, "Remote system to collect from (IP or hostname)");
cmd_taskhound.addArgFlagString("-u", "username", "Username for authentication", "");
cmd_taskhound.addArgFlagString("-p", "password", "Password for authentication", "");
cmd_taskhound.addArgFlagString("-save", "save_directory", "Directory to save XML files", "");
cmd_taskhound.addArgBool("-unsaved-creds", "Show tasks without stored credentials");
cmd_taskhound.addArgBool("-grab-blobs", "Also collect credential blobs and masterkeys (requires -save)");

cmd_taskhound.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = parsed_json["target"];
    let username = parsed_json["username"] || "";
    let password = parsed_json["password"] || "";
    let save_dir = parsed_json["save_directory"] || "";
    let flags = "";
    
    if(parsed_json["-unsaved-creds"]) { flags += "-unsaved-creds "; }
    if(parsed_json["-grab-blobs"]) { flags += "-grab-blobs"; }
    flags = flags.trim();
    
    // Build BOF arguments - fixed 5 parameter format for simplicity
    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr", 
        [target, username, password, save_dir, flags]);
    
    let bof_path = ax.script_dir() + "_bin/taskhound." + ax.arch(id) + ".o";
    let message = `BOF implementation: taskhound - Target: ${target}`;
    
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});


var group_test = ax.create_commands_group("SAR-BOF", [cmd_quser, cmd_taskhound]);
ax.register_commands_group(group_test, ["beacon", "gopher"], ["windows"], []);
