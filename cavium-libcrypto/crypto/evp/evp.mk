

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification
OBJS_$(d) := $(OBJ_DIR)/encode.o \
	$(OBJ_DIR)/digest.o \
	$(OBJ_DIR)/evp_enc.o \
	$(OBJ_DIR)/evp_key.o \
	$(OBJ_DIR)/evp_acnf.o \
	$(OBJ_DIR)/evp_cnf.o \
	$(OBJ_DIR)/e_des.o \
	$(OBJ_DIR)/e_bf.o \
	$(OBJ_DIR)/e_idea.o \
	$(OBJ_DIR)/e_des3.o \
	$(OBJ_DIR)/e_camellia.o \
	$(OBJ_DIR)/e_rc4.o \
	$(OBJ_DIR)/e_aes.o \
	$(OBJ_DIR)/names.o \
	$(OBJ_DIR)/e_seed.o \
	$(OBJ_DIR)/e_xcbc_d.o \
	$(OBJ_DIR)/e_rc2.o \
	$(OBJ_DIR)/e_cast.o \
	$(OBJ_DIR)/e_rc5.o \
	$(OBJ_DIR)/m_null.o \
	$(OBJ_DIR)/m_md2.o \
	$(OBJ_DIR)/m_md4.o \
	$(OBJ_DIR)/m_md5.o \
	$(OBJ_DIR)/m_sha.o \
	$(OBJ_DIR)/m_sha1.o \
	$(OBJ_DIR)/m_sha2.o \
	$(OBJ_DIR)/m_wp.o \
	$(OBJ_DIR)/m_dss.o \
	$(OBJ_DIR)/m_dss1.o \
	$(OBJ_DIR)/m_mdc2.o \
	$(OBJ_DIR)/m_ripemd.o \
	$(OBJ_DIR)/m_ecdsa.o \
	$(OBJ_DIR)/p_open.o \
	$(OBJ_DIR)/p_seal.o \
	$(OBJ_DIR)/p_sign.o \
	$(OBJ_DIR)/p_verify.o \
	$(OBJ_DIR)/p_lib.o \
	$(OBJ_DIR)/p_enc.o \
	$(OBJ_DIR)/p_dec.o \
	$(OBJ_DIR)/bio_md.o \
	$(OBJ_DIR)/bio_b64.o \
	$(OBJ_DIR)/bio_enc.o \
	$(OBJ_DIR)/evp_err.o \
	$(OBJ_DIR)/e_null.o \
	$(OBJ_DIR)/c_all.o \
	$(OBJ_DIR)/c_allc.o \
	$(OBJ_DIR)/c_alld.o \
	$(OBJ_DIR)/evp_lib.o \
	$(OBJ_DIR)/bio_ok.o \
	$(OBJ_DIR)/evp_pkey.o \
	$(OBJ_DIR)/evp_pbe.o \
	$(OBJ_DIR)/p5_crpt.o \
	$(OBJ_DIR)/p5_crpt2.o \
	$(OBJ_DIR)/e_old.o \
	$(OBJ_DIR)/pmeth_lib.o \
	$(OBJ_DIR)/pmeth_fn.o \
	$(OBJ_DIR)/pmeth_gn.o \
	$(OBJ_DIR)/m_sigver.o \
	$(OBJ_DIR)/evp_fips.o \
	$(OBJ_DIR)/e_aes_cbc_hmac_sha1.o \
	$(OBJ_DIR)/e_rc4_hmac_md5.o


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
