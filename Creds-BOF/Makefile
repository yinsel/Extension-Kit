CC64 = x86_64-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -DBOF -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) askcreds/askcreds.c -o _bin/askcreds.x64.o   && $(STRIP64) _bin/askcreds.x64.o) && echo '[+] askcreds' || echo '[!] askcreds'
	@($(CC64) $(CFLAGS) autologon/autologon.c -o _bin/autologon.x64.o && $(STRIP64) _bin/autologon.x64.o)  && echo '[+] autologon' || echo '[!] autologon'
	@($(CC64) $(CFLAGS) credman/credentialmanager.c -o _bin/credman.x64.o && $(STRIP64) _bin/credman.x64.o)  && echo '[+] credman' || echo '[!] credman'
	@($(CC64) $(CFLAGS) cookie-monster/cookie-monster-bof.c -o _bin/cookie-monster-bof.x64.o && $(STRIP64) _bin/cookie-monster-bof.x64.o)  && echo '[+] cookie-monster-bof' || echo '[!] cookie-monster-bof'
	@($(CC64) $(CFLAGS) hashdump/hashdump.c -o _bin/hashdump.x64.o && $(STRIP64) _bin/hashdump.x64.o)  && echo '[+] hashdump' || echo '[!] hashdump'
	@($(CC64) $(CFLAGS) get-netntlm/get-netntlm.c -o _bin/get-netntlm.x64.o && $(STRIP64) _bin/get-netntlm.x64.o)  && echo '[+] get-netntlm' || echo '[!] get-netntlm'
	@($(CC64) $(CFLAGS) -masm=intel UnderlayCopy/entry.c -o _bin/underlaycopy.x64.o && $(STRIP64) _bin/underlaycopy.x64.o)  && echo '[+] underlaycopy' || echo '[!] underlaycopy'

	@$(MAKE) --no-print-directory -C nanodump
	@cp nanodump/dist/*.o _bin/

clean:
	@(rm -rf _bin)
