# SPDX-License-Identifier: LGPL-2.1

include $(src)/scripts/utils.mk

bdir:=$(obj)/utest

TARGETS = $(bdir)/trace-utest

OBJS =
OBJS += trace-utest.o
OBJS += tracefs-utest.o

LIBTRACEFS_STATIC ?= $(obj)/lib/libtracefs.a

LIBS += -lcunit				\
	-ldl				\
	$(LIBTRACEFS_STATIC)

OBJS := $(OBJS:%.o=$(bdir)/%.o)

$(bdir):
	@mkdir -p $(bdir)

$(OBJS): | $(bdir)

$(bdir)/trace-utest: $(OBJS) $(LIBTRACEFS_STATIC)
	$(Q)$(do_app_build)

$(bdir)/%.o: %.c
	$(Q)$(call do_fpic_compile)

-include .*.d

test: $(TARGETS)

clean:
	$(Q)$(call do_clean,$(TARGETS) $(bdir)/*.o $(bdir)/.*.d)
