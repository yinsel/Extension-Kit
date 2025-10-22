all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c ldapsearch/ldapsearch.c -o _bin/ldapsearch.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/ldapsearch.x64.o) && echo '[+] ldapsearch' || echo '[!] ldapsearch'

	@$(MAKE) --no-print-directory -C Kerbeus-BOF
	@mv Kerbeus-BOF/_bin/Kerbeus-BOF _bin/



clean:
	@(rm -rf _bin)