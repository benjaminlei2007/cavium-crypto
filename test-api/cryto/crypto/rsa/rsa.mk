 


#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/rsa_eay.o \
	$(OBJ_DIR)/rsa_gen.o \
	$(OBJ_DIR)/rsa_lib.o \
	$(OBJ_DIR)/rsa_sign.o \
	$(OBJ_DIR)/rsa_saos.o \
	$(OBJ_DIR)/rsa_err.o \
	$(OBJ_DIR)/rsa_pk1.o \
	$(OBJ_DIR)/rsa_ssl.o \
	$(OBJ_DIR)/rsa_none.o \
	$(OBJ_DIR)/rsa_oaep.o \
	$(OBJ_DIR)/rsa_chk.o \
	$(OBJ_DIR)/rsa_null.o \
	$(OBJ_DIR)/rsa_pss.o \
	$(OBJ_DIR)/rsa_x931.o \
	$(OBJ_DIR)/rsa_asn1.o \
	$(OBJ_DIR)/rsa_depr.o \
	$(OBJ_DIR)/rsa_ameth.o \
	$(OBJ_DIR)/rsa_prn.o \
	$(OBJ_DIR)/rsa_pmeth.o \
	$(OBJ_DIR)/rsa_crpt.o \
    $(OBJ_DIR)/rsa_gen_generic.o	

$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -I$(d)/.. -I$(d)/../../include \
	-I$(d)/../../include/openssl $(CFLAGS_CRYPTO) $(RSA_CRT_VERIFY)

#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

-include $(DEPS_$(d))

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp))
