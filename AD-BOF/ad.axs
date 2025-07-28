var metadata = {
    name: "AD-BOF",
    description: "Active Directory Exploitation BOFs"
};

ax.script_import(ax.script_dir() + "Kerbeus-BOF/kerbeus.axs")

var cmd_ldapsearch = ax.create_command("ldapsearch", "Executes LDAP query", "ldapsearch (objectClass=*) -attributes *,ntsecuritydescriptor -count 40 -scope 2 -hostname DC1");
cmd_ldapsearch.addArgString("query", true);
cmd_ldapsearch.addArgFlagString( "-a", "attributes", "The attributes to retrieve", "*");
cmd_ldapsearch.addArgFlagInt( "-c", "count", "The result max size", 0);
cmd_ldapsearch.addArgFlagInt( "-s", "scope", "The scope to use: 1 = BASE, 2 = LEVEL, 3 = SUBTREE", 3);
cmd_ldapsearch.addArgFlagString( "--dc", "dc", "Hostname or IP to perform the LDAP connection on", "");
cmd_ldapsearch.addArgFlagString( "--dn", "dn", "The LDAP query basee", "");
cmd_ldapsearch.addArgBool( "--ldaps", "Using of LDAPS");
cmd_ldapsearch.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let query      = parsed_json["query"];
    let attributes = parsed_json["attributes"];
    let count      = parsed_json["count"];
    let scope      = parsed_json["scope"];
    let dc         = parsed_json["dc"];
    let dn         = parsed_json["dn"];
    let ldaps = 0;

    if (parsed_json["--ldaps"]) { ldaps = 1; }

    let bof_params = ax.bof_pack("wstr,cstr,int,int,cstr,cstr,int", [query, attributes, count, scope, dc, dn, ldaps]);
    let bof_path = ax.script_dir() + "_bin/ldapsearch." + ax.arch(id) + ".o";
    let message = "BOF implementation: ldapsearch";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

var group_exec = ax.create_commands_group("AD-BOF", [cmd_kerbeus, cmd_ldapsearch]);
ax.register_commands_group(group_exec, ["beacon", "gopher"], ["windows"], []);