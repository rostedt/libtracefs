# SPDX-License-Identifier: LGPL-2.1

include $(src)/scripts/utils.mk

OBJS =
OBJS += tracefs-utils.o
OBJS += tracefs-instance.o
OBJS += tracefs-events.o

OBJS := $(OBJS:%.o=$(bdir)/%.o)
DEPS := $(OBJS:$(bdir)/%.o=$(bdir)/.%.d)

$(LIBTRACEFS_STATIC): $(OBJS)
	$(Q)$(call do_build_static_lib)

$(LIBTRACEFS_SHARED): $(OBJS)
	$(Q)$(call do_compile_shared_library)
	@ln -sf $(@F) $(bdir)/libtracefs.so
	@ln -sf $(@F) $(bdir)/libtracefs.so.$(TFS_VERSION)

$(bdir)/%.o: %.c
	$(Q)$(call do_fpic_compile)

$(DEPS): $(bdir)/.%.d: %.c
	$(Q)$(CC) -M -MT $(bdir)/$*.o $(CPPFLAGS) $(CFLAGS) $< > $@

$(OBJS): $(bdir)/%.o : $(bdir)/.%.d

$(OBJS): | $(bdir)
$(DEPS): | $(bdir)

clean:
	$(RM) $(OBJS)

dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif
