#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d)	:= $(OBJ_DIR)/ech_lib.o $(OBJ_DIR)/ech_ossl.o $(OBJ_DIR)/ech_key.o $(OBJ_DIR)/ech_err.o


$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -I$(d)/.. -I$(d)/../../include \
	-I$(d)/../../include/openssl $(CFLAGS_CRYPTO)



#
#files:
#	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO
#
#links:
#	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
#	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
#	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

#install:
#	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
#	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
#	do  \
#	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
#	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
#	done;

#tags:
#	ctags $(SRC)

#tests:

#lint:
#	lint -DLINT $(INCLUDES) $(SRC)>fluff

#depend:
#	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
#	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

#dclean:
#	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
#	mv -f Makefile.new $(MAKEFILE)
#
#clean:
#	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.
#
#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

-include $(DEPS_$(d))

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp))
