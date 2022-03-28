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
OBJS += tracefs-filter.o
OBJS += tracefs-dynevents.o
OBJS += tracefs-eprobes.o
OBJS += tracefs-uprobes.o

# Order matters for the the three below
OBJS += sqlhist-lex.o
OBJS += sqlhist.tab.o
OBJS += tracefs-sqlhist.o

OBJS := $(OBJS:%.o=$(bdir)/%.o)
DEPS := $(OBJS:$(bdir)/%.o=$(bdir)/.%.d)

$(LIBTRACEFS_STATIC): $(OBJS)
	$(Q)$(call do_build_static_lib)

$(LIBTRACEFS_SHARED): $(OBJS)
	$(Q)$(call do_compile_shared_library,$(notdir $(LIBTRACEFS_SHARED_VERSION)))

$(LIBTRACEFS_SHARED_VERSION): $(LIBTRACEFS_SHARED)
	@ln -sf $(<F) $@

$(LIBTRACEFS_SHARED_SO): $(LIBTRACEFS_SHARED_VERSION)
	@ln -sf $(<F) $@

libtracefs.so: $(LIBTRACEFS_SHARED_SO)

# bison will create both sqlhist.tab.c and sqlhist.tab.h
sqlhist.tab.h:
sqlhist.tab.c: sqlhist.y sqlhist.tab.h
	bison --debug -v --report-file=bison.report -d -o $@ $<

sqlhist-lex.c: sqlhist.l sqlhist.tab.c
	flex -o $@ $<

$(bdir)/%.o: %.c
	$(Q)$(call do_fpic_compile)

$(DEPS): $(bdir)/.%.d: %.c
	$(Q)$(CC) -M -MT $(bdir)/$*.o $(CPPFLAGS) $(CFLAGS) $< > $@

$(OBJS): $(bdir)/%.o : $(bdir)/.%.d

tracefs-sqlhist.o: sqlhist.tab.h

$(OBJS): | $(bdir)
$(DEPS): | $(bdir)

clean:
	$(Q)$(call do_clean,$(OBJS) .*.d)

dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif

$(bdir)/tracefs-sqlhist.o tracefs-sqlhist.o: sqlhist.tab.h

.PHONY: $(LIBTRACEFS_SHARED_SO) $(LIBTRACEFS_STATIC)
