CC64 = x86_64-w64-mingw32-gcc
CPP64 = x86_64-w64-mingw32-g++
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -DBOF -s -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) psexec/psexec.c -o _bin/psexec.x64.o && $(STRIP64) _bin/psexec.x64.o) && echo '[+] psexec' || echo '[!] psexec'
	@($(CC64) $(CFLAGS) scshell/scshell.c -o _bin/scshell.x64.o && $(STRIP64) _bin/scshell.x64.o) && echo '[+] scshell' || echo '[!] scshell'
	@($(CC64) $(CFLAGS) token_make/token_make.c -o _bin/token_make.x64.o && $(STRIP64) _bin/token_make.x64.o) && echo '[+] token_make' || echo '[!] token_make'
	@($(CC64) $(CFLAGS) token_steal/token_steal.c -o _bin/token_steal.x64.o && $(STRIP64) _bin/token_steal.x64.o) && echo '[+] token_steal' || echo '[!] token_steal'
	@($(CC64) $(CFLAGS) runas/runas.c -o _bin/runas.x64.o && $(STRIP64) _bin/token_steal.x64.o) && echo '[+] runas' || echo '[!] runas'
	@($(CPP64) -I ../_include -w -Os -s -c -masm=intel -nostdlib -Wno-nonnull -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti winrm-client/winrm.cpp -o _bin/winrm.x64.o && $(STRIP64) _bin/winrm.x64.o) && echo '[+] winrm' || echo '[!] winrm'

clean:
	@(rm -rf _bin)
