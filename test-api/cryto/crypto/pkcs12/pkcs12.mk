 


#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/p12_add.o \
	$(OBJ_DIR)/p12_asn.o \
	$(OBJ_DIR)/p12_attr.o \
	$(OBJ_DIR)/p12_crpt.o \
	$(OBJ_DIR)/p12_crt.o \
	$(OBJ_DIR)/p12_decr.o \
	$(OBJ_DIR)/p12_init.o \
	$(OBJ_DIR)/p12_key.o \
	$(OBJ_DIR)/p12_kiss.o \
	$(OBJ_DIR)/p12_mutl.o \
	$(OBJ_DIR)/p12_utl.o \
	$(OBJ_DIR)/p12_npas.o \
	$(OBJ_DIR)/pk12err.o \
	$(OBJ_DIR)/p12_p8d.o \
	$(OBJ_DIR)/p12_p8e.o

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
