
#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification
OBJS_$(d) := $(OBJ_DIR)/eng_err.o \
	$(OBJ_DIR)/eng_lib.o \
	$(OBJ_DIR)/eng_list.o \
	$(OBJ_DIR)/eng_init.o \
	$(OBJ_DIR)/eng_ctrl.o \
	$(OBJ_DIR)/eng_table.o \
	$(OBJ_DIR)/eng_pkey.o \
	$(OBJ_DIR)/eng_fat.o \
	$(OBJ_DIR)/eng_all.o \
	$(OBJ_DIR)/tb_rsa.o \
	$(OBJ_DIR)/tb_dsa.o \
	$(OBJ_DIR)/tb_ecdsa.o \
	$(OBJ_DIR)/tb_dh.o \
	$(OBJ_DIR)/tb_ecdh.o \
	$(OBJ_DIR)/tb_rand.o \
	$(OBJ_DIR)/tb_store.o \
	$(OBJ_DIR)/tb_cipher.o \
	$(OBJ_DIR)/tb_digest.o \
	$(OBJ_DIR)/tb_pkmeth.o \
	$(OBJ_DIR)/tb_asnmth.o \
	$(OBJ_DIR)/tb_eceg.o \
	$(OBJ_DIR)/eng_openssl.o \
	$(OBJ_DIR)/eng_cnf.o \
	$(OBJ_DIR)/eng_dyn.o \
	$(OBJ_DIR)/eng_cryptodev.o \
	$(OBJ_DIR)/eng_rsax.o \
	$(OBJ_DIR)/eng_rdrand.o


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
