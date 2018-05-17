
#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification
OBJS_$(d) := $(OBJ_DIR)/a_object.o \
	$(OBJ_DIR)/a_bitstr.o \
	$(OBJ_DIR)/a_utctm.o \
	$(OBJ_DIR)/a_gentm.o \
	$(OBJ_DIR)/a_time.o \
	$(OBJ_DIR)/a_int.o \
	$(OBJ_DIR)/a_octet.o \
	$(OBJ_DIR)/a_print.o \
	$(OBJ_DIR)/a_type.o \
	$(OBJ_DIR)/a_set.o \
	$(OBJ_DIR)/a_dup.o \
	$(OBJ_DIR)/a_d2i_fp.o \
	$(OBJ_DIR)/a_i2d_fp.o \
	$(OBJ_DIR)/a_enum.o \
	$(OBJ_DIR)/a_utf8.o \
	$(OBJ_DIR)/a_sign.o \
	$(OBJ_DIR)/a_digest.o \
	$(OBJ_DIR)/a_verify.o \
	$(OBJ_DIR)/a_mbstr.o \
	$(OBJ_DIR)/a_strex.o \
	$(OBJ_DIR)/x_algor.o \
	$(OBJ_DIR)/x_val.o \
	$(OBJ_DIR)/x_pubkey.o \
	$(OBJ_DIR)/x_sig.o \
	$(OBJ_DIR)/x_req.o \
	$(OBJ_DIR)/x_attrib.o \
	$(OBJ_DIR)/x_bignum.o \
	$(OBJ_DIR)/x_long.o \
	$(OBJ_DIR)/x_name.o \
	$(OBJ_DIR)/x_x509.o \
	$(OBJ_DIR)/x_x509a.o \
	$(OBJ_DIR)/x_crl.o \
	$(OBJ_DIR)/x_info.o \
	$(OBJ_DIR)/x_spki.o \
	$(OBJ_DIR)/nsseq.o \
	$(OBJ_DIR)/x_nx509.o \
	$(OBJ_DIR)/d2i_pu.o \
	$(OBJ_DIR)/d2i_pr.o \
	$(OBJ_DIR)/i2d_pu.o \
	$(OBJ_DIR)/i2d_pr.o \
	$(OBJ_DIR)/t_req.o \
	$(OBJ_DIR)/t_x509.o \
	$(OBJ_DIR)/t_x509a.o \
	$(OBJ_DIR)/t_crl.o \
	$(OBJ_DIR)/t_pkey.o \
	$(OBJ_DIR)/t_spki.o \
	$(OBJ_DIR)/t_bitst.o \
	$(OBJ_DIR)/tasn_new.o \
	$(OBJ_DIR)/tasn_fre.o \
	$(OBJ_DIR)/tasn_enc.o \
	$(OBJ_DIR)/tasn_dec.o \
	$(OBJ_DIR)/tasn_utl.o \
	$(OBJ_DIR)/tasn_typ.o \
	$(OBJ_DIR)/tasn_prn.o \
	$(OBJ_DIR)/ameth_lib.o \
	$(OBJ_DIR)/f_int.o \
	$(OBJ_DIR)/f_string.o \
	$(OBJ_DIR)/n_pkey.o \
	$(OBJ_DIR)/f_enum.o \
	$(OBJ_DIR)/x_pkey.o \
	$(OBJ_DIR)/a_bool.o \
	$(OBJ_DIR)/x_exten.o \
	$(OBJ_DIR)/bio_asn1.o \
	$(OBJ_DIR)/bio_ndef.o \
	$(OBJ_DIR)/asn_mime.o \
	$(OBJ_DIR)/asn1_gen.o \
	$(OBJ_DIR)/asn1_par.o \
	$(OBJ_DIR)/asn1_lib.o \
	$(OBJ_DIR)/asn1_err.o \
	$(OBJ_DIR)/a_bytes.o \
	$(OBJ_DIR)/a_strnid.o \
	$(OBJ_DIR)/evp_asn1.o \
	$(OBJ_DIR)/asn_pack.o \
	$(OBJ_DIR)/p5_pbe.o \
	$(OBJ_DIR)/p5_pbev2.o \
	$(OBJ_DIR)/p8_pkey.o \
	$(OBJ_DIR)/asn_moid.o


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
