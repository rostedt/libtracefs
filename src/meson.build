# SPDX-License-Identifier: LGPL-2.1
#
# Copyright (c) 2023 Daniel Wagner, SUSE LLC

sources= [
   'tracefs-dynevents.c',
   'tracefs-eprobes.c',
   'tracefs-events.c',
   'tracefs-filter.c',
   'tracefs-hist.c',
   'tracefs-instance.c',
   'tracefs-kprobes.c',
   'tracefs-marker.c',
   'tracefs-record.c',
   'tracefs-sqlhist.c',
   'tracefs-tools.c',
   'tracefs-uprobes.c',
   'tracefs-utils.c',
]

flex = find_program('flex', required: true)
bison = find_program('bison', required: true)

lgen = generator(flex,
output : '@PLAINNAME@.yy.c',
arguments : ['-o', '@OUTPUT@', '@INPUT@'])

pgen = generator(bison,
output : ['@BASENAME@.tab.c', '@BASENAME@.tab.h'],
arguments : ['@INPUT@', '--defines=@OUTPUT1@', '--output=@OUTPUT0@'])

lfiles = lgen.process('sqlhist.l')
pfiles = pgen.process('sqlhist.y')

libtracefs = library(
    'tracefs',
    sources, lfiles, pfiles,
    version: library_version,
    dependencies: [libtraceevent_dep, threads_dep],
    include_directories: [incdir],
    install: true)

libtracefs_static = static_library(
    'tracefs_static',
    sources, lfiles, pfiles,
    dependencies: [libtraceevent_dep, threads_dep],
    include_directories: [incdir],
    install: false)

pkg = import('pkgconfig')
pkg.generate(
    libtracefs,
    libraries: [libtraceevent_dep],
    subdirs: 'libtracefs',
    filebase: meson.project_name(),
    name: meson.project_name(),
    version: meson.project_version(),
    description: 'Manage trace fs',
    url: 'https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git/')

libtracefs_dep = declare_dependency(
    include_directories: ['.'],
    link_with: libtracefs)
