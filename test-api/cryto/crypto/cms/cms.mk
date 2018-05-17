

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/cms_lib.o \
	$(OBJ_DIR)/cms_asn1.o \
	$(OBJ_DIR)/cms_att.o \
	$(OBJ_DIR)/cms_io.o \
	$(OBJ_DIR)/cms_smime.o \
	$(OBJ_DIR)/cms_err.o \
	$(OBJ_DIR)/cms_sd.o \
	$(OBJ_DIR)/cms_dd.o \
	$(OBJ_DIR)/cms_cd.o \
	$(OBJ_DIR)/cms_env.o \
	$(OBJ_DIR)/cms_enc.o \
	$(OBJ_DIR)/cms_ess.o \
	$(OBJ_DIR)/cms_pwri.o

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
