all: dir bof

clean:
	@(rm -f _bin/*)

dir:
	@(mkdir _bin 2>/dev/null) && echo '[+] creating _bin' || echo '[*] _bin exists'

bof:
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/execute-assembly.x64.o -I ./_include/ -Os -s -c execute-assembly/inlineExecute-Assembly.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/execute-assembly.x64.o) && echo '[*] execute-assembly' || echo '[!] execute-assembly build failed'
