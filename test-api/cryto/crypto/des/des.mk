

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/set_key.o \
	$(OBJ_DIR)/ecb_enc.o \
	$(OBJ_DIR)/cbc_enc.o \
	$(OBJ_DIR)/ecb3_enc.o \
	$(OBJ_DIR)/cfb64enc.o \
	$(OBJ_DIR)/cfb64ede.o \
	$(OBJ_DIR)/cfb_enc.o \
	$(OBJ_DIR)/ofb64ede.o \
	$(OBJ_DIR)/enc_read.o \
	$(OBJ_DIR)/enc_writ.o \
	$(OBJ_DIR)/ofb64enc.o \
	$(OBJ_DIR)/ofb_enc.o \
	$(OBJ_DIR)/str2key.o \
	$(OBJ_DIR)/pcbc_enc.o \
	$(OBJ_DIR)/qud_cksm.o \
	$(OBJ_DIR)/rand_key.o \
	$(OBJ_DIR)/des_enc.o \
	$(OBJ_DIR)/fcrypt_b.o \
	$(OBJ_DIR)/fcrypt.o \
	$(OBJ_DIR)/xcbc_enc.o \
	$(OBJ_DIR)/rpc_enc.o \
	$(OBJ_DIR)/cbc_cksm.o \
	$(OBJ_DIR)/ede_cbcm_enc.o \
	$(OBJ_DIR)/des_old.o \
	$(OBJ_DIR)/des_old2.o \
	$(OBJ_DIR)/read2pwd.o \

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
