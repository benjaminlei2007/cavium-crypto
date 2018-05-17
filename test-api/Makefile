ifndef OCTEON_ROOT
OCTEON_ROOT = ../..
endif

ifndef OCTEON_MODE
OCTEON_MODE = se
endif

ifeq ($(OCTEON_MODE),se)
export OCTEON_TARGET=cvmx_64
else
 ifeq ($(OCTEON_MODE),seum)
 export OCTEON_TARGET=linux_64
 endif
endif

all: application-target  moretargets 

#set RSA_CRT_VERIFY to -DCAV_RSA_CRT_VERIFY to verify
#the modexp operation using the CRT implementation.
#RSA_CRT_VERIFY=
RSA_CRT_VERIFY = -DCVM_RSA_CRT_VERIFY


#  standard common Makefile fragment

include $(OCTEON_ROOT)/common.mk

ifeq ($(OCTEON_MODE),seum)
export PREFIX=-seum
endif
#  include relevant component Makefile fragments

include cflags-crypto.mk

dir := $(OCTEON_ROOT)/executive
include $(dir)/cvmx.mk


dir := $(PWD)/../
include $(dir)/crypto.mk

OBJS = $(OBJ_DIR)/test-symmetric-api.o
CFLAGS_LOCAL += -g -O2 -W -Wall -Wno-unused-parameter 
CFLAGS_LOCAL += -I$(OCTEON_ROOT)/target/include -I../crypto -I../include -I./include
CFLAGS_LOCAL += $(CFLAGS_CRYPTO)
CFLAGS_LOCAL += -DOCTEON_MODEL=$(OCTEON_MODEL)

ifneq ($(OCTEON_MODEL),$(filter $(OCTEON_MODEL),OCTEON_CN73XX OCTEON_CN78XX_PASS2_0))
CFLAGS_LOCAL += -DSHA3_MODE=1
endif

include $(OCTEON_ROOT)/application.mk

moretargets: test-crypto-api$(PREFIX)


test-crypto-api$(PREFIX):obj_dep
	$(CC) $(CFLAGS_LOCAL)  $(OBJ_DIR)/test-crypto-api.o \
		$(OBJ_DIR)/test-modes-api.o \
        $(OBJ_DIR)/test-drbg-api.o $(OBJ_DIR)/test-hash-api.o \
        $(OBJ_DIR)/test-aes-f8f9.o $(OBJ_DIR)/test-dhgroup19.o \
        $(OBJ_DIR)/test-asymmetric-api.o $(OBJ_DIR)/test-kasumi-api.o \
        $(OBJ_DIR)/test-snow3g-api.o $(OBJ_DIR)/test-ipsec-api.o \
        $(OBJ_DIR)/test-ecdsa-api.o $(OBJ_DIR)/test-ecdh-api.o \
        $(OBJ_DIR)/test-tkip-api.o $(OBJ_DIR)/test-dhgroup20.o \
		$(OBJ_DIR)/test-camellia-api.o   $(OBJ_DIR)/test-zuc-api.o  \
        $(OBJ_DIR)/test-dhgroup24.o   $(OBJ_DIR)/test-eceg-api.o  \
		$(OBJ_DIR)/test-ec-point.o $(OBJ_DIR)/test-symmetric-api.o $(LIBS_LIST) $(LDFLAGS_GLOBAL) -o $@

obj_dep: $(CVMX_CONFIG) $(OBJ_DIR) $(OBJ_DIR)/test-ec-point.o $(OBJ_DIR)/test-symmetric-api.o $(OBJ_DIR)/test-modes-api.o $(OBJ_DIR)/test-zuc-api.o  $(OBJ_DIR)/test-dhgroup19.o $(OBJ_DIR)/test-ecdh-api.o $(OBJ_DIR)/test-eceg-api.o $(OBJ_DIR)/test-hash-api.o $(OBJ_DIR)/test-camellia-api.o  $(OBJ_DIR)/test-asymmetric-api.o  $(OBJ_DIR)/test-drbg-api.o $(OBJ_DIR)/test-kasumi-api.o $(OBJ_DIR)/test-dhgroup20.o $(OBJ_DIR)/test-snow3g-api.o $(OBJ_DIR)/test-tkip-api.o $(OBJ_DIR)/test-dhgroup24.o $(OBJ_DIR)/test-ipsec-api.o $(OBJ_DIR)/test-crypto-api.o $(OBJ_DIR)/test-ecdsa-api.o $(OBJ_DIR)/test-aes-f8f9.o $(LIBS_LIST)

final:
	cp -f $(TARGET) $(TARGET).stripped
	$(STRIP) $(TARGET).stripped

run: $(TARGET)
	oct-sim $(TARGET) -quiet -numcores=1 -noperf

clean:
	rm -rf $(TARGET) $(OBJ_DIR) $(CVMX_CONFIG) test-crypto-api$(PREFIX) 


