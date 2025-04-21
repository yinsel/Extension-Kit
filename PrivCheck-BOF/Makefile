all: dir bof

clean:
	@(rm -f _bin/* && rm -f _include/vulndrivers.h && echo '[*] cleaned')

dir:
	@(mkdir _bin 2>/dev/null) && echo '[+] creating _bin' || echo '[*] _bin exists'

bof:
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/alwayselevated.x64.o -I ./_include/ -Os -s -c privcheck/alwaysinstallelevated.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/alwayselevated.x64.o) && echo '[*] alwayselevated' || echo '[!] alwayselevated build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/autologon.x64.o -I ./_include/ -Os -s -c privcheck/autologon.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/autologon.x64.o) && echo '[*] autologon' || echo '[!] autologon build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/credman.x64.o -I ./_include/ -Os -s -c privcheck/credentialmanager.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/credman.x64.o) && echo '[*] credman' || echo '[!] credman build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/hijackablepath.x64.o -I ./_include/ -Os -s -c privcheck/hijackablepath.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/hijackablepath.x64.o) && echo '[*] hijackablepath' || echo '[!] hijackablepath build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/tokenpriv.x64.o -I ./_include/ -Os -s -c privcheck/tokenprivileges.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/tokenpriv.x64.o) && echo '[*] tokenpriv' || echo '[!] tokenpriv build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/unattendfiles.x64.o -I ./_include/ -Os -s -c privcheck/unattendfiles.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/unattendfiles.x64.o) && echo '[*] unattendfiles' || echo '[!] unattendfiles build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/unquotedsvc.x64.o -I ./_include/ -Os -s -c privcheck/unquotedsvcpath.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/unquotedsvc.x64.o) && echo '[*] unquotedsvc' || echo '[!] unquotedsvc build failed'
	@(python3 download_vulnerable_driver_list.py)
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/vulndrivers.x64.o -I ./_include/ -Os -s -c privcheck/vulnerabledrivers.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/vulndrivers.x64.o) && echo '[*] vulndrivers' || echo '[!] vulndrivers build failed'
