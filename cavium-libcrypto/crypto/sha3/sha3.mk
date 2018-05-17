
#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

ifneq ($(OCTEON_MODEL),$(filter $(OCTEON_MODEL),OCTEON_CN73XX OCTEON_CN78XX_PASS2_0))
	SHA3_FLAGS=-DSHA3_MODE=1 -DPLATFORM_BYTE_ORDER -DUNROLL_CHILOOP
	OBJS_$(d) := $(OBJ_DIR)/sha3dgst.o \
	$(OBJ_DIR)/sha3dgst_sw.o \
	$(OBJ_DIR)/KeccakF-1600-reference.o \
	$(OBJ_DIR)/sha3_sponge.o \
	$(OBJ_DIR)/SnP-FBWL-default.o
else
	SHA3_FLAGS=
	OBJS_$(d) := $(OBJ_DIR)/sha3dgst.o
endif

$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -I$(d)/.. -I$(d)/../../include \
	-I$(d)/../../include/openssl $(SHA3_FLAGS) $(CFLAGS_CRYPTO)

#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

-include $(DEPS_$(d))

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp))
