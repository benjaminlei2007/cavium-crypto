 


#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/ocsp_asn.o \
	$(OBJ_DIR)/ocsp_ext.o \
	$(OBJ_DIR)/ocsp_ht.o \
	$(OBJ_DIR)/ocsp_lib.o \
	$(OBJ_DIR)/ocsp_cl.o \
	$(OBJ_DIR)/ocsp_srv.o \
	$(OBJ_DIR)/ocsp_prn.o \
	$(OBJ_DIR)/ocsp_vfy.o \
	$(OBJ_DIR)/ocsp_err.o

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
