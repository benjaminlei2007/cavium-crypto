

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir1)

#  component specification

OBJS_$(d) := $(d)/cbc128.o \
	$(d)/ctr128.o \
	$(d)/cts128.o \
	$(d)/cfb128.o \
	$(d)/ofb128.o \
	$(d)/gcm128.o \
	$(d)/ccm128.o \
	$(d)/xts128.o

$(OBJS_$(d)):

#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

$(d)/%.o:	$(d)/%.c
	$(CC) $(CFLAGS_LOCAL) $(CFLAGS_GLOBAL) -MD -c -o $@ $<

-include $(DEPS_$(d))

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp))
