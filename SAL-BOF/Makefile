CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -w -Wno-incompatible-pointer-types -Os -DBOF -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) arp/arp.c -o _bin/arp.x64.o && $(STRIP64) _bin/arp.x64.o) && echo '[+] arp' || echo '[!] arp'
	@($(CC64) $(CFLAGS) cacls/cacls.c -o _bin/cacls.x64.o && $(STRIP64) _bin/cacls.x64.o) && echo '[+] cacls' || echo '[!] cacls'
	@($(CC64) $(CFLAGS) dir/dir.c -o _bin/dir.x64.o && $(STRIP64) _bin/dir.x64.o) && echo '[+] dir' || echo '[!] dir'
	@($(CC64) $(CFLAGS) env/env.c -o _bin/env.x64.o && $(STRIP64) _bin/env.x64.o) && echo '[+] env' || echo '[!] env'
	@($(CC64) $(CFLAGS) ipconfig/ipconfig.c -o _bin/ipconfig.x64.o && $(STRIP64) _bin/ipconfig.x64.o) && echo '[+] ipconfig' || echo '[!] ipconfig'
	@($(CC64) $(CFLAGS) listdns/listdns.c -o _bin/listdns.x64.o && $(STRIP64) _bin/listdns.x64.o) && echo '[+] listdns' || echo '[!] listdns'
	@($(CC64) $(CFLAGS) netstat/netstat.c -o _bin/netstat.x64.o && $(STRIP64) _bin/netstat.x64.o) && echo '[+] netstat' || echo '[!] netstat'
	@($(CC64) $(CFLAGS) -fno-jump-tables nslookup/nslookup.c -o _bin/nslookup.x64.o && $(STRIP64) _bin/nslookup.x64.o) && echo '[+] nslookup' || echo '[!] nslookup'
	@($(CC64) $(CFLAGS) routeprint/routeprint.c -o _bin/routeprint.x64.o && $(STRIP64) _bin/routeprint.x64.o) && echo '[+] routeprint' || echo '[!] routeprint'
	@($(CC64) $(CFLAGS) uptime/uptime.c -o _bin/uptime.x64.o && $(STRIP64) _bin/uptime.x64.o) && echo '[+] uptime' || echo '[!] uptime'
	@($(CC64) $(CFLAGS) useridletime/useridletime.c -o _bin/useridletime.x64.o && $(STRIP64) _bin/useridletime.x64.o) && echo '[+] useridletime' || echo '[!] useridletime'
	@($(CC64) $(CFLAGS) whoami/whoami.c -o _bin/whoami.x64.o && $(STRIP64) _bin/whoami.x64.o) && echo '[+] whoami' || echo '[!] whoami'
	@(python3 ./privcheck/download_vulnerable_driver_list.py)
	@($(CC64) $(CFLAGS) privcheck/vulnerabledrivers.c -o _bin/vulndrivers.x64.o && $(STRIP64) _bin/vulndrivers.x64.o) && echo '[+] vulnerabledrivers' || echo '[!] vulnerabledrivers'
	@($(CC64) $(CFLAGS) privcheck/alwaysinstallelevated.c -o _bin/alwayselevated.x64.o && $(STRIP64) _bin/alwayselevated.x64.o) && echo '[+] alwayselevated' || echo '[!] alwayselevated'
	@($(CC64) $(CFLAGS) privcheck/hijackablepath.c -o _bin/hijackablepath.x64.o && $(STRIP64) _bin/hijackablepath.x64.o) && echo '[+] hijackablepath' || echo '[!] hijackablepath'
	@($(CC64) $(CFLAGS) privcheck/tokenprivileges.c -o _bin/tokenpriv.x64.o && $(STRIP64) _bin/tokenpriv.x64.o) && echo '[+] tokenpriv' || echo '[!] tokenpriv'
	@($(CC64) $(CFLAGS) privcheck/unattendfiles.c -o _bin/unattendfiles.x64.o && $(STRIP64) _bin/unattendfiles.x64.o) && echo '[+] unattendfiles' || echo '[!] unattendfiles'
	@($(CC64) $(CFLAGS) privcheck/unquotedsvcpath.c -o _bin/unquotedsvc.x64.o && $(STRIP64) _bin/unquotedsvc.x64.o) && echo '[+] unquotedsvc' || echo '[!] unquotedsvc'

clean:
	@(rm -rf _bin)
