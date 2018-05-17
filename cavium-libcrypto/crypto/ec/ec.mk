#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/ec_lib.o \
	$(OBJ_DIR)/ecp_smpl.o \
	$(OBJ_DIR)/ecp_mont.o \
	$(OBJ_DIR)/ecp_nist.o \
	$(OBJ_DIR)/ec_cvt.o \
	$(OBJ_DIR)/ec_mult.o \
	$(OBJ_DIR)/ec_err.o \
	$(OBJ_DIR)/ec_curve.o \
	$(OBJ_DIR)/ec_check.o \
	$(OBJ_DIR)/ec_print.o \
	$(OBJ_DIR)/ec_asn1.o \
	$(OBJ_DIR)/ec_key.o \
	$(OBJ_DIR)/ec2_smpl.o \
	$(OBJ_DIR)/ec2_mult.o \
	$(OBJ_DIR)/ec_ameth.o \
	$(OBJ_DIR)/ec_pmeth.o \
	$(OBJ_DIR)/eck_prn.o \
	$(OBJ_DIR)/ecp_nistp224.o \
	$(OBJ_DIR)/ecp_nistp256.o \
	$(OBJ_DIR)/ecp_nistp521.o \
	$(OBJ_DIR)/ecp_nistputil.o \
	$(OBJ_DIR)/ecp_oct.o \
	$(OBJ_DIR)/ec2_oct.o \
	$(OBJ_DIR)/ec_oct.o  \
	$(OBJ_DIR)/fecc_SubP384.o \
	$(OBJ_DIR)/fecc_ConstMulP256.o \
	$(OBJ_DIR)/fecc_ConstMulP384.o \
	$(OBJ_DIR)/fecc_SubP256.o \
	$(OBJ_DIR)/fecc_ArithP256B17731.o \
	$(OBJ_DIR)/fecc_ArithP384B17731.o \
	$(OBJ_DIR)/fecc_ArithP521B17731.o \
	$(OBJ_DIR)/fecc_SubP521.o \
	$(OBJ_DIR)/fecc_ConstMulP521.o \
	$(OBJ_DIR)/ecp_hmg.o \
	$(OBJ_DIR)/fecc_MulP256o3.o \
	$(OBJ_DIR)/fecc_MulP384o3.o \
	$(OBJ_DIR)/fecc_MulP521o3.o


$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -I$(d)/.. -I$(d)/../../include \
	-I$(d)/../../include/openssl $(CFLAGS_CRYPTO) -g -DOPENSSL_NO_EC_NISTP_64_GCC_128 

#EXHEADER= ec.h
#HEADER=	ec_lcl.h $(EXHEADER)

#ALL=    $(GENERAL) $(SRC) $(HEADER)

#top:
#	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)



#files:
#	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

#links:
#	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
#	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
#	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

#install:
#	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
#	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
#	do  \
#	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
#	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;
#


#depend:
#	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
#	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

#dclean:
#	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
#	mv -f Makefile.new $(MAKEFILE)

#clean:
#	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

#
#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

$(OBJ_DIR)/%.o: $(d)/%.S
	$(ASSEMBLE)
	
-include $(DEPS_$(d))

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp)) DO NOT DELETE THIS LINE -- make depend depends on it.
