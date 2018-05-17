# Makefile
# Copyright (c) 2003-2006, Cavium Networks. All rights reserved.
#
# This Software is the property of Cavium Networks. The Software and all 
# accompanying documentation are copyrighted. The Software made available here 
# constitutes the proprietary information of Cavium Networks. You agree to take  
# reasonable steps to prevent the disclosure, unauthorized use or unauthorized 
# distribution of the Software. You shall use this Software solely with Cavium 
# hardware. 
#
# Except as expressly permitted in a separate Software License Agreement 
# between You and Cavium Networks, You shall not modify, decompile, 
# disassemble, extract, or otherwise reverse engineer this Software. You shall
# not make any copy of the Software or its accompanying documentation, except 
# for copying incident to the ordinary and intended use of the Software and 
# the Underlying Program and except for the making of a single archival copy.
#
# This Software, including technical data, may be subject to U.S. export 
# control laws, including the U.S. Export Administration Act and its 
# associated regulations, and may be subject to export or import regulations 
# in other countries. You warrant that You will comply strictly in all 
# respects with all such regulations and acknowledge that you have the 
# responsibility to obtain licenses to export, re-export or import the 
# Software.
#
# TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND 
# WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, 
# EITHER EXPRESS,IMPLIED, STATUTORY,OR OTHERWISE, WITH RESPECT TO THE SOFTWARE,
# INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION, 
# OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY 
# DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, 
# NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES,ACCURACY OR
# COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO 
# DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE 
# SOFTWARE LIES WITH YOU.

include $(OCTEON_ROOT)/common.mk

OPENSSL_VERSION?=1.0.1g

# OpenSSL Install Path
OPENSSL_TOP_DIR		= $(OCTEON_ROOT)/linux/embedded_rootfs/build/openssl-${OPENSSL_VERSION}

#Library Name
LIBNAME=libocteon

INCLUDES		+= -I. -I./camellia -I./modes -I./des -I./modexp -I./aes -I./rsa -I./sha -I./md5

#OpenSSL Includes
INCLUDES 		+= -I$(OPENSSL_TOP_DIR)/include

CFLAGS_GLOBAL += -fPIC
CFLAGS_GLOBAL += -Wno-error
CFLAGS_LOCAL  += $(DEFINES) $(INCLUDES) -O3 -Wall 

ifneq ($(findstring OCTEON_CN7, $(OCTEON_MODEL)),)
    CFLAGS_LOCAL += -DOCTEON3
endif


OBJ= mul_lin.o e_octeon.o aes_gcm_engine.o

SHLIBNAME=$(LIBNAME).so

ifeq (,$(findstring linux,$(OCTEON_TARGET)))
   ${error Invalid value for OCTEON_TARGET. Supported values: linux_64, linux_n32}
else
   ifeq (linux_o32, $(OCTEON_TARGET))
      ${error Invalid value for OCTEON_TARGET. Supported values: linux_64, linux_n32}
   endif
endif

all: check engine

check:
	@if [ ! -d $(OPENSSL_TOP_DIR) ]; then \
		echo "OpenSSL Top Directory does not exist \n"; \
		exit 1; \
	fi

%.o: %.c
	$(CC) $(CFLAGS_LOCAL) $(CFLAGS_GLOBAL) -MD -c -o $@ $<

dirdes = ./des
include $(dirdes)/des.mk
OBJ += $(OBJS_$(dirdes))

dirmodexp = ./modexp
include $(dirmodexp)/modexp.mk
OBJ += $(OBJS_$(dirmodexp))

diraes = ./aes
include $(diraes)/aes.mk
OBJ += $(OBJS_$(diraes))

dirsha = ./sha
include $(dirsha)/sha.mk
OBJ += $(OBJS_$(dirsha))

dirmd5 = ./md5
include $(dirmd5)/md5.mk
OBJ += $(OBJS_$(dirmd5))

ifneq ($(findstring OCTEON_CN7, $(OCTEON_MODEL)),)
dir1 = ./modes
include $(dir1)/modes.mk
OBJ += $(OBJS_$(dir1))

dir2 = ./camellia
include $(dir2)/cmll.mk
OBJ += $(OBJS_$(dir2))
endif

%.o: %.S
	$(ASSEMBLE) 

engine:	 $(OBJ)
	$(CC) $(CFLAGS_GLOBAL) -shared -o $(SHLIBNAME) $(OBJ) -L$(OPENSSL_TOP_DIR) -lcrypto

clean:
	@rm -f *.o *.so
