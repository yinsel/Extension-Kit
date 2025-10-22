all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@(x86_64-w64-mingw32-gcc -I _include -Os -masm=intel -c ldapsearch/ldapsearch.c -o _bin/ldapsearch.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/ldapsearch.x64.o) && echo '[+] ldapsearch' || echo '[!] ldapsearch'
	@(x86_64-w64-mingw32-gcc -I _include -Os -masm=intel -c adwssearch/adws_search.c -o _bin/adws_search.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/adws_search.x64.o) && echo '[+] adws_search' || echo '[!] adws_search'

	@ # x86: -DWOW64 -fno-leading-underscore

	@$(MAKE) --no-print-directory -C Kerbeus-BOF
	@mv Kerbeus-BOF/_bin/Kerbeus-BOF _bin/

	@$(MAKE) --no-print-directory -C SQL-BOF
	@mv SQL-BOF/_bin/SQL _bin/

clean:
	@(rm -rf _bin)