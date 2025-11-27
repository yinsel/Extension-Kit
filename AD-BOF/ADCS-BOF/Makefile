
all: bof

bof:
	@(mkdir -p _bin/ADCS 2>/dev/null) && echo 'creating _bin/ADCS' || echo '_bin/ADCS exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/ADCS/certi_enum.x64.o -Os -s -DBOF -c src/enum/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/ADCS/certi_enum.x64.o) && echo '[+] enum' || echo '[!] enum'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/ADCS/certi_req.x64.o -I ./src/_common -Os -s -DBOF -c src/request/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/ADCS/certi_req.x64.o) && echo '[+] certi_req' || echo '[!] certi_req'

clean:
	@(rm -rf _bin)