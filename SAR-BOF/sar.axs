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


var group_test = ax.create_commands_group("SAR-BOF", [cmd_quser]);
ax.register_commands_group(group_test, ["beacon", "gopher"], ["windows"], []);
