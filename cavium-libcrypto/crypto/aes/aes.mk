

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/aes_core.o \
	$(OBJ_DIR)/aes_misc.o \
	$(OBJ_DIR)/aes_ecb.o \
	$(OBJ_DIR)/aes_cbc.o \
	$(OBJ_DIR)/aes_cfb.o \
	$(OBJ_DIR)/aes_ofb.o \
	$(OBJ_DIR)/aes_ctr.o \
	$(OBJ_DIR)/aes_icm.o \
	$(OBJ_DIR)/cvm_aes.o \
	$(OBJ_DIR)/aes_xcbc.o \
	$(OBJ_DIR)/aes_prf.o \
	$(OBJ_DIR)/aes_gcm.o \
	$(OBJ_DIR)/aes_lrw.o \
	$(OBJ_DIR)/aes_xts.o \
	$(OBJ_DIR)/aes_cmac.o \
	$(OBJ_DIR)/aes_ccm.o \
	$(OBJ_DIR)/aes_xcb.o \
	$(OBJ_DIR)/aes_wrap.o

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
