# SPDX-License-Identifier: LGPL-2.1
#
# Copyright (c) 2023 Daniel Wagner, SUSE LLC

source = [
    'trace-utest.c',
    'tracefs-utest.c',
]

e = executable(
   'trace-utest',
   source,
   include_directories: [incdir],
   dependencies: [libtraceevent_dep, threads_dep, cunit_dep],
   link_with: libtracefs_static)

test('trace-utest', e)
