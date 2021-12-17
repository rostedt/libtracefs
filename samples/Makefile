# SPDX-License-Identifier: LGPL-2.1

#
# The samples are pulled out of the examples used in the man pages
# that are located in the Documentation directory.
#

include $(src)/scripts/utils.mk

EXAMPLES :=
EXAMPLES += dynevents
EXAMPLES += kprobes
EXAMPLES += eprobes
EXAMPLES += synth
EXAMPLES += error
EXAMPLES += filter
EXAMPLES += function-filter
EXAMPLES += hist
EXAMPLES += hist-cont
EXAMPLES += tracer
EXAMPLES += stream

TARGETS :=
TARGETS += sqlhist
TARGETS += $(EXAMPLES)

bdir := $(obj)/bin

all: $(TARGETS)

extract_example = \
	cat $1 | sed -ne '/^EXAMPLE/,/FILES/ { /EXAMPLE/,+2d ; /^FILES/d ;  /^--/d ; p}' > $2

$(bdir)/sqlhist.c: ../Documentation/libtracefs-sql.txt
	$(call extract_example,$<,$@)

EXAMPLE_C_CODE := $(patsubst %,$(bdir)/%.c,$(EXAMPLES))

$(bdir)/%.c: ../Documentation/libtracefs-%.txt
	$(call extract_example,$<,$@)

$(bdir):
	@mkdir -p $(bdir)

sqlhist: $(bdir) $(bdir) $(bdir)/sqlhist

$(TARGETS): $(bdir)

# sqlhist is unique and stands on its own
sqlhist: $(bdir)/sqlhist

$(bdir)/%: $(bdir)/%.o
	$(CC) -o $@ $^ $(LIBTRACEFS_STATIC) $(LIBTRACEEVENT_LIBS)

$(EXAMPLES): $(patsubst %,$(bdir)/%,$(TARGETS))

## The intermediate files get removed by Make.
## To examine the .c files created by one of the man pages,
## uncomment the below, and replace the XX with the exec example
## name, and the file will not be discarded by make.
#
# $(bdir)/XX.o: $(bdir)/XX.c
#	$(CC) -g -Wall -c -o $@ $^ -I../include/ $(LIBTRACEEVENT_INCLUDES)

$(bdir)/%.o: %.c
	$(CC) -g -Wall -c $(CFLAGS) -o $@ $^ -I../include/ $(LIBTRACEEVENT_INCLUDES)

clean:
	$(RM) $(bdir)/*
