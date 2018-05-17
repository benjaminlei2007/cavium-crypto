
#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification
OBJS_$(d) := $(OBJ_DIR)/v3_bcons.o \
	$(OBJ_DIR)/v3_bitst.o \
	$(OBJ_DIR)/v3_conf.o \
	$(OBJ_DIR)/v3_extku.o \
	$(OBJ_DIR)/v3_ia5.o \
	$(OBJ_DIR)/v3_lib.o \
	$(OBJ_DIR)/v3_prn.o \
	$(OBJ_DIR)/v3_utl.o \
	$(OBJ_DIR)/v3err.o \
	$(OBJ_DIR)/v3_genn.o \
	$(OBJ_DIR)/v3_alt.o \
	$(OBJ_DIR)/v3_skey.o \
	$(OBJ_DIR)/v3_akey.o \
	$(OBJ_DIR)/v3_pku.o \
	$(OBJ_DIR)/v3_int.o \
	$(OBJ_DIR)/v3_enum.o \
	$(OBJ_DIR)/v3_sxnet.o \
	$(OBJ_DIR)/v3_cpols.o \
	$(OBJ_DIR)/v3_crld.o \
	$(OBJ_DIR)/v3_purp.o \
	$(OBJ_DIR)/v3_info.o \
	$(OBJ_DIR)/v3_ocsp.o \
	$(OBJ_DIR)/v3_akeya.o \
	$(OBJ_DIR)/v3_pmaps.o \
	$(OBJ_DIR)/v3_pcons.o \
	$(OBJ_DIR)/v3_ncons.o \
	$(OBJ_DIR)/v3_pcia.o \
	$(OBJ_DIR)/v3_pci.o \
	$(OBJ_DIR)/pcy_cache.o \
	$(OBJ_DIR)/pcy_node.o \
	$(OBJ_DIR)/pcy_data.o \
	$(OBJ_DIR)/pcy_map.o \
	$(OBJ_DIR)/pcy_tree.o \
	$(OBJ_DIR)/pcy_lib.o \
	$(OBJ_DIR)/v3_asid.o \
	$(OBJ_DIR)/v3_addr.o


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
