 


#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification
OBJS_$(d) := $(OBJ_DIR)/bio_lib.o \
	$(OBJ_DIR)/bio_cb.o \
	$(OBJ_DIR)/bio_err.o \
	$(OBJ_DIR)/bss_mem.o \
	$(OBJ_DIR)/bss_null.o \
	$(OBJ_DIR)/bss_fd.o \
	$(OBJ_DIR)/bss_file.o \
	$(OBJ_DIR)/bf_null.o \
	$(OBJ_DIR)/bf_buff.o \
	$(OBJ_DIR)/b_print.o \
	$(OBJ_DIR)/b_dump.o \
	$(OBJ_DIR)/bf_nbio.o \
	$(OBJ_DIR)/bss_bio.o \
	#$(OBJ_DIR)/bss_conn.o \
	$(OBJ_DIR)/bss_log.o \
	$(OBJ_DIR)/b_sock.o \
	$(OBJ_DIR)/bss_dgram.o


$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -I$(d)/.. -I$(d)/../../include \
	-I$(d)/../../include/openssl -fno-builtin-pow10 $(CFLAGS_CRYPTO)

#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

-include $(DEPS_$(d))

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp))
