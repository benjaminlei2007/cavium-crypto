
#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/bn_add.o \
	$(OBJ_DIR)/bn_div.o \
	$(OBJ_DIR)/bn_exp.o \
	$(OBJ_DIR)/bn_lib.o \
	$(OBJ_DIR)/bn_ctx.o \
	$(OBJ_DIR)/bn_mul.o \
	$(OBJ_DIR)/bn_mod.o \
	$(OBJ_DIR)/bn_print.o \
	$(OBJ_DIR)/bn_rand.o \
	$(OBJ_DIR)/bn_shift.o \
	$(OBJ_DIR)/bn_word.o \
	$(OBJ_DIR)/bn_blind.o \
	$(OBJ_DIR)/bn_kron.o \
	$(OBJ_DIR)/bn_sqrt.o \
	$(OBJ_DIR)/bn_gcd.o \
	$(OBJ_DIR)/bn_err.o \
	$(OBJ_DIR)/bn_sqr.o \
	$(OBJ_DIR)/bn_asm.o \
	$(OBJ_DIR)/bn_recp.o \
	$(OBJ_DIR)/bn_mont.o \
	$(OBJ_DIR)/bn_mpi.o \
	$(OBJ_DIR)/bn_exp2.o \
	$(OBJ_DIR)/bn_prime.o \
	$(OBJ_DIR)/bn_nist.o  \
	$(OBJ_DIR)/bn_gf2m.o \
	$(OBJ_DIR)/bn_prime_generic.o


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
