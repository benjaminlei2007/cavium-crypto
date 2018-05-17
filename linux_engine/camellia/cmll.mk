
#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir2)

#  component specification

OBJS_$(d) := $(d)/camellia.o \
	$(d)/cmll_misc.o \
	$(d)/cmll_ecb.o \
	$(d)/cmll_cbc.o \
	$(d)/cmll_cfb.o \
	$(d)/cmll_ofb.o \
	$(d)/cmll_utl.o
#	$(d)/cmll_ctr.o \

$(OBJS_$(d)):

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

$(d)/%.o:	$(d)/%.c
	$(CC) $(CFLAGS_LOCAL) $(CFLAGS_GLOBAL) -MD -c -o $@ $<

-include $(DEPS_$(d))

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp))
