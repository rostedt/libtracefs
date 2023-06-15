# SPDX-License-Identifier: LGPL-2.1
#
# Copyright (c) 2023 Daniel Wagner, SUSE LLC

examples = [
    'dynevents',
    'kprobes',
    'eprobes',
    'uprobes',
    'synth',
    'error',
    'filter',
    'function-filter',
    'hist',
    'hist-cont',
    'tracer',
    'stream',
    'instances-affinity',
    'cpu',
]

extract_examples = find_program('extract-example.sh')
gen = generator(
   extract_examples,
   output: '@BASENAME@.c',
   arguments: ['@INPUT@', '@OUTPUT@'])

foreach ex : examples
    src = gen.process(meson.current_source_dir() + '/../Documentation/libtracefs-@0@.txt'.format(ex))
    executable(
        ex.underscorify(),
        src,
        dependencies: [libtracefs_dep, libtraceevent_dep, threads_dep],
        include_directories: [incdir])
endforeach

# sqlhist is unique and stands on its own
src = gen.process(meson.current_source_dir() + '/../Documentation/libtracefs-sql.txt')
executable(
   'sqlhist',
   src,
   dependencies: [libtracefs_dep, libtraceevent_dep, threads_dep],
   include_directories: [incdir],
   install: true,
   install_dir: bindir)
