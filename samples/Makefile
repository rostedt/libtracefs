# SPDX-License-Identifier: LGPL-2.1

#
# The samples are pulled out of the examples used in the man pages
# that are located in the Documentation directory.
#

include $(src)/scripts/utils.mk

TARGETS :=
TARGETS += sqlhist
TARGETS += dynevent

bdir := $(obj)/bin

all: $(TARGETS)

extract_example = \
	cat $1 | sed -ne '/^EXAMPLE/,/FILES/ { /EXAMPLE/,+2d ; /^FILES/d ;  /^--/d ; p}' > $2

$(bdir)/sqlhist.c: ../Documentation/libtracefs-sql.txt
	$(call extract_example,$<,$@)

$(bdir)/dynevent.c: ../Documentation/libtracefs-dynevents.txt
	$(call extract_example,$<,$@)

$(bdir):
	@mkdir -p $(bdir)

sqlhist: $(bdir) $(bdir) $(bdir)/sqlhist

$(TARGETS): $(bdir)

$(bdir)/%: $(bdir)/%.o
	$(CC) -o $@ $^ $(LIBTRACEFS_STATIC) $(LIBTRACEEVENT_LIBS)

$(TARGETS): $(patsubst %,$(bdir)/%,$(TARGETS))

$(bdir)/%.o: %.c
	$(CC) -g -Wall -c -o $@ $^ -I../include/ $(LIBTRACEEVENT_INCLUDES)

clean:
	$(RM) $(bdir)/*
