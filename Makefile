SAFARI ?= /Applications/MobileSafari.app/MobileSafari
dump: safari safari.objdump safari.xxd safari.otool disassembly
safari:
	ssh wanderer cat $(SAFARI) > ~/downloads/$@
	ln -s ~/downloads/$@ .
safari.objdump:
	ssh wanderer objdump --disassemble $(SAFARI) > ~/downloads/$@
	ln -s ~/downloads/$@ .
safari.xxd:
	ssh wanderer cat $(SAFARI) | xxd > ~/downloads/$@
	ln -s ~/downloads/$@ .
safari.otool:
	ssh wanderer otool -tV $(SAFARI) > ~/downloads/$@
	ln -s ~/downloads/$@ .
safari_header.otool:
	ssh wanderer otool -h $(SAFARI) > ~/downloads/$@
	ln -s ~/downloads/$@ .
safari_load.otool:
	ssh wanderer otool -l $(SAFARI) > ~/downloads/$@
	ln -s ~/downloads/$@ .
safari_libs.otool:
	ssh wanderer otool -L $(SAFARI) > ~/downloads/$@
	ln -s ~/downloads/$@ .
safari_data.otool:
	ssh wanderer otool -d $(SAFARI) > ~/downloads/$@
	ln -s ~/downloads/$@ .
safari_reloc.otool:
	ssh wanderer otool -rv $(SAFARI) > ~/downloads/$@
	ln -s ~/downloads/$@ .
safari_symtab.otool:
	ssh wanderer otool -Iv $(SAFARI) > ~/downloads/$@
	ln -s ~/downloads/$@ .
safari_hints.otool:
	ssh wanderer otool -Hv $(SAFARI) > ~/downloads/$@
	ln -s ~/downloads/$@ .
otool: safari_header.otool safari_load.otool safari_libs.otool \
 safari_data.otool safari_reloc.otool safari_symtab.otool safari_hints.otool

disassembly: macho.py safari
	./$+
doctest: macho.py
	./$<
patchtest: patchsafari
	@echo restoring already-patched safari
	./$< restore
	@echo re-patching restored safari
	./$< patch
macho: macho.py
	$(MAKE) --silent disassembly > /tmp/safari.dsm
	./$< /tmp/safari.dsm > /tmp/safaricheck
	./$< /tmp/safaricheck > /tmp/safaricheck.dsm
	-diff /tmp/safari.dsm /tmp/safaricheck.dsm
	diff safari /tmp/safaricheck
