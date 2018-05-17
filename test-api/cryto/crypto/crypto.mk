
#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) := $(OBJ_DIR)/cryptlib.o \
	$(OBJ_DIR)/crypto-generic-api.o \
	$(OBJ_DIR)/crypto_ipsec_api.o \
	$(OBJ_DIR)/mem.o \
	$(OBJ_DIR)/mem_dbg.o \
	$(OBJ_DIR)/mem_clr.o \
	$(OBJ_DIR)/ex_data.o \
	$(OBJ_DIR)/f8-f9.o \
	$(OBJ_DIR)/uea1-uia1.o \
	$(OBJ_DIR)/uea2-uia2.o \
	$(OBJ_DIR)/eea2-eia2.o \
	$(OBJ_DIR)/o_time.o \
	$(OBJ_DIR)/mem.o \
	$(OBJ_DIR)/mem_clr.o \
	$(OBJ_DIR)/mem_dbg.o \
	$(OBJ_DIR)/cpt_err.o \
	$(OBJ_DIR)/ebcdic.o \
	$(OBJ_DIR)/uid.o \
	$(OBJ_DIR)/o_time.o \
	$(OBJ_DIR)/o_str.o \
	$(OBJ_DIR)/o_fips.o \
	$(OBJ_DIR)/o_init.o \
	$(OBJ_DIR)/fips_ers.o

$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -I$(d)/../include \
	-I$(d)/../include/openssl $(CFLAGS_CRYPTO)

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

dir := $(d)/bf
include $(dir)/bf.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/buffer
include $(dir)/buffer.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/cast
include $(dir)/cast.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/cmac
include $(dir)/cmac.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/cms
include $(dir)/cms.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/comp
include $(dir)/comp.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/dso
include $(dir)/dso.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/ecdsa
include $(dir)/ecdsa.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/eceg
include $(dir)/eceg.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/idea
include $(dir)/idea.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/jpake
include $(dir)/jpake.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/krb5
include $(dir)/krb5.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/mdc2
include $(dir)/mdc2.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/sha
include $(dir)/sha.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/sha3
include $(dir)/sha3.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/md5
include $(dir)/md5.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/des
include $(dir)/des.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/dsa
include $(dir)/dsa.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/rsa
include $(dir)/rsa.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/dh
include $(dir)/dh.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/rc2
include $(dir)/rc2.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/rc4
include $(dir)/rc4.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/rc5
include $(dir)/rc5.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/hmac
include $(dir)/hmac.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/modes
include $(dir)/modes.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/aes
include $(dir)/aes.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/camellia
include $(dir)/cmll.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/zuc
include $(dir)/zuc.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/evp
include $(dir)/evp.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/err
include $(dir)/err.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/bn
include $(dir)/bn.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/stack
include $(dir)/stack.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/buffer
include $(dir)/buffer.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/engine
include $(dir)/engine.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/lhash
include $(dir)/lhash.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/x509
include $(dir)/x509.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/rand
include $(dir)/rand.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/objects
include $(dir)/objects.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/asn1
include $(dir)/asn1.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/bio
include $(dir)/bio.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/ecdh
include $(dir)/ecdh.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/ec
include $(dir)/ec.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/modexp
include $(dir)/modexp.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/x509v3
include $(dir)/x509v3.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/pkcs7
include $(dir)/pkcs7.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/pkcs12
include $(dir)/pkcs12.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/pqueue
include $(dir)/pqueue.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/md2
include $(dir)/md2.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/pem
include $(dir)/pem.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/conf
include $(dir)/conf.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/ocsp
include $(dir)/ocsp.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/ripemd
include $(dir)/ripemd.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/seed
include $(dir)/seed.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/srp
include $(dir)/srp.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/store
include $(dir)/store.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/ts
include $(dir)/ts.mk
OBJS_$(d) += $(OBJS_$(dir))


dir := $(d)/whrlpool
include $(dir)/whrlpool.mk
OBJS_$(d) += $(OBJS_$(dir))

dir := $(d)/tkip
include $(dir)/tkip.mk
OBJS_$(d) += $(OBJS_$(dir))

$(LIBRARY): $(OBJS_$(d))
	$(AR) -r $@ $^

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp))
