# SPDX-License-Identifier: LGPL-2.1

include $(src)/scripts/utils.mk

OBJS =
OBJS += tracefs-utils.o
OBJS += tracefs-instance.o
OBJS += tracefs-events.o
OBJS += tracefs-tools.o
OBJS += tracefs-marker.o
OBJS += tracefs-kprobes.o
OBJS += tracefs-hist.o

OBJS := $(OBJS:%.o=$(bdir)/%.o)
DEPS := $(OBJS:$(bdir)/%.o=$(bdir)/.%.d)

LIBTRACEFS_SHARED_SO = $(bdir)/libtracefs.so
LIBTRACEFS_SHARED_VERSION = $(bdir)/libtracefs.so.$(TFS_VERSION)

$(LIBTRACEFS_STATIC): $(OBJS)
	$(Q)$(call do_build_static_lib)

$(LIBTRACEFS_SHARED): $(OBJS)
	$(Q)$(call do_compile_shared_library,$(notdir $(LIBTRACEFS_SHARED_VERSION)))

$(LIBTRACEFS_SHARED_VERSION): $(LIBTRACEFS_SHARED)
	@ln -sf $(<F) $@

$(LIBTRACEFS_SHARED_SO): $(LIBTRACEFS_SHARED_VERSION)
	@ln -sf $(<F) $@

libtracefs.so: $(LIBTRACEFS_SHARED_SO)

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
