

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/buffer.o \
	$(OBJ_DIR)/buf_str.o \
	$(OBJ_DIR)/buf_err.o

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
