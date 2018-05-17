
#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/x509_def.o \
	$(OBJ_DIR)/x509_d2.o \
	$(OBJ_DIR)/x509_r2x.o \
	$(OBJ_DIR)/x509_cmp.o \
	$(OBJ_DIR)/x509_obj.o \
	$(OBJ_DIR)/x509_req.o \
	$(OBJ_DIR)/x509spki.o \
	$(OBJ_DIR)/x509_vfy.o \
	$(OBJ_DIR)/x509_set.o \
	$(OBJ_DIR)/x509cset.o \
	$(OBJ_DIR)/x509rset.o \
	$(OBJ_DIR)/x509_err.o \
	$(OBJ_DIR)/x509name.o \
	$(OBJ_DIR)/x509_v3.o \
	$(OBJ_DIR)/x509_ext.o \
	$(OBJ_DIR)/x509_att.o \
	$(OBJ_DIR)/x509type.o \
	$(OBJ_DIR)/x509_lu.o \
	$(OBJ_DIR)/x_all.o \
	$(OBJ_DIR)/x509_txt.o \
	$(OBJ_DIR)/x509_trs.o \
	$(OBJ_DIR)/by_file.o \
	$(OBJ_DIR)/by_dir.o \
	$(OBJ_DIR)/x509_vpm.o

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
