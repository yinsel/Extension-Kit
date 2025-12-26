CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -DBOF -s -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) ScreenshotBOF/entry.c -o _bin/Screenshot.x64.o && $(STRIP64) _bin/Screenshot.x64.o) && echo '[+] Screenshot' || echo '[!] Screenshot'
	@($(CC64) $(CFLAGS) firewallrule/addfirewallrule.c -o _bin/addfirewallrule.x64.o && $(STRIP64) _bin/addfirewallrule.x64.o) && echo '[+] addfirewallrule' || echo '[!] addfirewallrule'
	@($(CC64) $(CFLAGS) SauronEyeBOF/entry.c -o _bin/sauroneye.x64.o && $(STRIP64) _bin/sauroneye.x64.o) && echo '[+] sauroneye' || echo '[!] sauroneye'

clean:
	@(rm -rf _bin)
