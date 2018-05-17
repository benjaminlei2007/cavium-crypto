

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/dsa_gen.o \
	$(OBJ_DIR)/dsa_key.o \
	$(OBJ_DIR)/dsa_lib.o \
	$(OBJ_DIR)/dsa_asn1.o \
	$(OBJ_DIR)/dsa_vrf.o \
	$(OBJ_DIR)/dsa_sign.o \
	$(OBJ_DIR)/dsa_err.o \
	$(OBJ_DIR)/dsa_ossl.o \
	$(OBJ_DIR)/dsa_depr.o \
	$(OBJ_DIR)/dsa_ameth.o \
	$(OBJ_DIR)/dsa_pmeth.o \
	$(OBJ_DIR)/dsa_prn.o \
	$(OBJ_DIR)/dsa_key_generic.o \
	$(OBJ_DIR)/dsa_gen_generic.o

$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -I$(d)/.. -I$(d)/../../include \
	-I$(d)/../../include/openssl $(CFLAGS_CRYPTO)

#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

-include $(DEPS_$(d))

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp))
