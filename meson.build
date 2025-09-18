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

# mctp-i3c
executable('mctp-i3c', 'mctp-i3c/mctp-i3c.c', install: true)

# mctp-socket
executable('mctp-skt-req', 'mctp-socket/mctp-req.c', 'mctp-socket/mctp-util.c', install: true)
executable('mctp-skt-recv', 'mctp-socket/mctp-recv.c', install: true)

# eSPI
executable('oob-pch-test', 'espi_test/oob-pch-test.c', install: true)

# mctp
executable('mctp-ast', ['mctp/mctp.c', 'mctp/libmctp.c'], install: true,
    include_directories: include_directories('mctp'), dependencies: thread_dep)

# mem_utils
executable('md', ['mem_utils/md.c', 'mem_utils/mem_common.c'], install: true)
executable('mw', ['mem_utils/mw.c', 'mem_utils/mem_common.c'], install: true)

# svf
executable('svf', ['svf/main.c', 'svf/ast-jtag.c', 'svf/svf.c'], install: true)

# otp
platform = get_option('otp-platform')
if platform == 'ast2700'
  otp_src = ['otp/otp_ast2700.c', 'otp/lib_otp_ast2700.c', 'otp/otp_prov.c']
elif platform == 'ast2600'
  otp_src = 'otp/otp_ast2600.c'
else
  error('Invalid otp-platform: ' + platform)
endif
executable('otp', otp_src, install: true, dependencies: dependency('openssl'),
    include_directories: include_directories('otp'))

# usb
executable('hid_gadget_app', 'usb/hid_gadget_test.c', install: true)

# cptra
executable('aspeed_cptra', 'cptra/aspeed_cptra.c', install: true)
