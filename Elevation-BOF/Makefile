
all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin' || echo '_bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -o _bin/getsystem_token.x64.o -I ./ -Os -s -c getsystem_token/getsystem_token.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/getsystem_token.x64.o) && echo '[*] getsystem_token' || echo '[X] getsystem_token'
