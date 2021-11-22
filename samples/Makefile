# SPDX-License-Identifier: LGPL-2.1

#
# The samples are pulled out of the examples used in the man pages
# that are located in the Documentation directory.
#

include $(src)/scripts/utils.mk

bdir := $(obj)/bin

$(bdir):
	@mkdir -p $(bdir)

sqlhist: $(bdir) $(bdir) $(bdir)/sqlhist

$(bdir)/sqlhist: $(bdir)/sqlhist.o $(LIBTRACEFS_STATIC)
	$(CC) -o $@ $^ $(LIBTRACEEVENT_LIBS)

$(bdir)/sqlhist.c: ../Documentation/libtracefs-sql.txt
	cat $< | sed -ne '/^EXAMPLE/,/FILES/ { /EXAMPLE/,+2d ; /^FILES/d ;  /^--/d ; p}' > $@

$(bdir)/sqlhist.o: $(bdir)/sqlhist.c
	$(CC) -g -Wall -c -o $@ $^ -I../include/ $(LIBTRACEEVENT_INCLUDES)

clean:
	$(RM) $(bdir)/*
