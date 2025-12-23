CC64 = x86_64-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../../_include -w -Wno-incompatible-pointer-types -Os -s -DBOF -c

all: bof

bof:
	@(mkdir -p _bin/ADCS 2>/dev/null) && echo 'creating _bin/ADCS' || echo '_bin/ADCS exists'
	@($(CC64) $(CFLAGS) src/enum/entry.c -o _bin/ADCS/certi_enum.x64.o   && $(STRIP64) _bin/ADCS/certi_enum.x64.o) && echo '[+] enum' || echo '[!] enum'
	@($(CC64) $(CFLAGS) src/request/entry.c -o _bin/ADCS/certi_req.x64.o && $(STRIP64) _bin/ADCS/certi_req.x64.o)  && echo '[+] certi_req' || echo '[!] certi_req'

clean:
	@(rm -rf _bin)