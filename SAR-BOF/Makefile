CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -DBOF -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) -s smartscan/portscan_simple.c -o _bin/smartscan.x64.o && $(STRIP64) _bin/smartscan.x64.o) && echo '[+] smartscan' || echo '[!] smartscan'
	@($(CC64) $(CFLAGS) -s nbtscan/nbtscan.c -o _bin/nbtscan.x64.o && $(STRIP64) _bin/nbtscan.x64.o) && echo '[+] nbtscan' || echo '[!] nbtscan'
	@($(CC64) $(CFLAGS) taskhound/taskhound.c -o _bin/taskhound.x64.o && $(STRIP64) _bin/taskhound.x64.o) && echo '[+] taskhound' || echo '[!] taskhound'
	@($(CC64) $(CFLAGS) quser/quser.c -o _bin/quser.x64.o && $(STRIP64) _bin/quser.x64.o) && echo '[+] quser' || echo '[!] quser'

clean:
	@(rm -rf _bin)