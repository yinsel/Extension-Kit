all: dir bof

clean:
	@(rm -f _bin/* && echo '[*] cleaned')

dir:
	@(mkdir _bin 2>/dev/null) && echo '[+] creating _bin' || echo '[*] _bin exists'

bof:
	@(x86_64-w64-mingw32-gcc -w -o _bin/sspi.x64.o -I ./_include/ -Os -s -c sspi/SspiUacBypassBOF.cpp && x86_64-w64-mingw32-strip --strip-unneeded _bin/sspi.x64.o) && echo '[*] sspi' || echo '[!] sspi build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/regshellcmd.x64.o -I ./_include/ -Os -s -c regshellcmd/RegistryShellCommandBOF.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/regshellcmd.x64.o) && echo '[*] regshellcmd' || echo '[!] regshellcmd build failed'
