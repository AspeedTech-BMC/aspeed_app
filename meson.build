project('aspeed-app', 'c', 'cpp', version: '1.0.0')
thread_dep = dependency('threads')

# rvas
librvas = library('rvas', 'ast_rvas/rvas_lib/rvas.c', install: true, version: meson.project_version(),
    dependencies: thread_dep, include_directories: include_directories('ast_rvas/rvas_lib'))
executable('vtest', ['ast_rvas/vtest.c'], install: true, link_with: librvas,
    dependencies: thread_dep, include_directories: include_directories('ast_rvas/rvas_lib'))
executable('rvas_test', ['ast_rvas/rvas_test.c'], install: true, link_with: librvas,
    dependencies: thread_dep, include_directories: include_directories('ast_rvas/rvas_lib'))

# Video
executable('ast-video', ['video/ikvm_video.cpp', 'video/main1.cc', 'video/main2.cc', 'video/main.cc', 'video/video.cc', 'video/bmp.cc'], install: true)
install_data('video/video.inf')

# i2c
executable('i2c-test', 'i2c-test/i2c-test.c', install: true,
    dependencies: thread_dep)

executable('i2c-slave-mqueue', 'i2c-slave-mqueue/i2c-slave-mqueue.c', install: true)

# i3c
executable('i3c-test', 'i3c-test/i3c-test.c', install: true)

# eSPI
executable('oob-pch-test', 'espi_test/oob-pch-test.c', install: true)

# mctp
executable('mctp', ['mctp/mctp.c', 'mctp/libmctp.c'], install: true,
    include_directories: include_directories('mctp'), dependencies: thread_dep)

# mem_utils
executable('md', ['mem_utils/md.c', 'mem_utils/mem_common.c'], install: true)
executable('mw', ['mem_utils/mw.c', 'mem_utils/mem_common.c'], install: true)
executable('spd', ['mem_utils/spd.c', 'mem_utils/mem_common.c'], install: true)
executable('spw', ['mem_utils/spw.c', 'mem_utils/mem_common.c'], install: true)

# svf
executable('svf', ['svf/main.c', 'svf/ast-jtag.c', 'svf/svf.c'], install: true)

# otp
executable('otp', ['otp/otp.c', 'otp/sha256.c'], install: true,
    include_directories: include_directories('otp'))
