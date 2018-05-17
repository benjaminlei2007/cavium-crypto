

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/ts_err.o \
	$(OBJ_DIR)/ts_req_utils.o \
	$(OBJ_DIR)/ts_req_print.o \
	$(OBJ_DIR)/ts_rsp_utils.o \
	$(OBJ_DIR)/ts_rsp_print.o \
	$(OBJ_DIR)/ts_rsp_sign.o \
	$(OBJ_DIR)/ts_rsp_verify.o \
	$(OBJ_DIR)/ts_verify_ctx.o \
	$(OBJ_DIR)/ts_lib.o \
	$(OBJ_DIR)/ts_conf.o \
	$(OBJ_DIR)/ts_asn1.o

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
