# SPDX-License-Identifier: LGPL-2.1
#
# Copyright (c) 2023 Daniel Wagner, SUSE LLC

project(
    'libtracefs', ['c'],
    meson_version: '>= 0.50.0',
    license: 'LGPL-2.1',
    version: '1.8',
    default_options: [
        'c_std=gnu99',
        'buildtype=debug',
        'default_library=both',
        'prefix=/usr/local',
        'warning_level=1'])

library_version = meson.project_version()

libtraceevent_dep = dependency('libtraceevent', version: '>= 1.8.1', required: true)
threads_dep = dependency('threads', required: true)
cunit_dep = dependency('cunit', required : false)

prefixdir = get_option('prefix')
bindir = join_paths(prefixdir, get_option('bindir'))
mandir = join_paths(prefixdir, get_option('mandir'))
htmldir = join_paths(prefixdir, get_option('htmldir'))

add_project_arguments(
    [
        '-D_GNU_SOURCE',
    ],
    language : 'c')

incdir = include_directories(['include'])

subdir('src')
subdir('include')
if cunit_dep.found()
    subdir('utest')
endif
if get_option('samples')
subdir('samples')
endif

if get_option('doc')
subdir('Documentation')

custom_target(
    'docs',
    output: 'docs',
    depends: [html, man],
    command: ['echo'])
endif
