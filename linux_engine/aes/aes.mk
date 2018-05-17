

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(diraes)

#  component specification

OBJS_$(d) := $(d)/aes_cbc.o $(d)/aes_ecb.o

$(OBJS_$(d)):  

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

$(d)/%.o:	$(d)/%.c
	$(CC) $(CFLAGS_LOCAL) $(CFLAGS_GLOBAL) -MD -c -o $@ $<

-include $(DEPS_$(d))

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp))
