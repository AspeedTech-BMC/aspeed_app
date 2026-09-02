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
  executable('otp', ['otp/otp_ast2700.c', 'otp/lib_otp_ast2700.c', 'otp/otp_prov.c'],
      install: true, dependencies: dependency('openssl'),
      include_directories: include_directories('otp'))
elif platform == 'ast2705'
  executable('otp-ast2705', 'otp/otp_ast2705.c',
      install: true,
      include_directories: include_directories('otp'))
elif platform == 'ast2600'
  executable('otp', 'otp/otp_ast2600.c',
      install: true, dependencies: dependency('openssl'),
      include_directories: include_directories('otp'))
else
  error('Invalid otp-platform: ' + platform)
endif

# usb
executable('hid_gadget_app', 'usb/hid_gadget_test.c', install: true)

# cptra
if host_machine.cpu_family() == 'aarch64'
  # cptra-platform picks which single binary gets built -- the two are never
  # built together. Must be set explicitly, e.g. -Dcptra-platform=ast2700.
  cptra_platform = get_option('cptra-platform')
  if cptra_platform not in ['ast2700', 'ast2705']
    error('cptra-platform must be set to "ast2700" or "ast2705", e.g. -Dcptra-platform=ast2700')
  endif

  if cptra_platform == 'ast2700'
    mbedtls_inc = include_directories('lib/mbedtls/include')
    mbedtls_lib_dir = meson.current_source_dir() / 'lib' / 'mbedtls' / 'library'
    mbedtls_user_cfg = meson.current_source_dir() / 'cptra' / 'mbedtls_user_config.h'

    # Delegate to a wrapper script to avoid complex shell quoting issues when
    # bitbake invokes the build commands. CC/AR must be forwarded explicitly
    # -- otherwise the wrapper's `make` falls back to the build machine's
    # native toolchain and produces libs in the wrong ELF format to link
    # against this (possibly cross-compiled) target.
    mbedtls_cc = meson.get_compiler('c')
    mbedtls_ar = find_program('ar')
    mbedtls_make = custom_target('mbedtls_lib',
      output: ['libmbedcrypto.a', 'libmbedx509.a', 'libmbedtls.a'],
      command: [
        'sh', meson.current_source_dir() / 'cptra' / 'build_mbedtls.sh',
        meson.current_source_dir() / 'lib' / 'mbedtls',
        mbedtls_user_cfg,
        '@OUTDIR@',
        ' '.join(mbedtls_cc.cmd_array()),
        mbedtls_ar.full_path()
      ],
      depend_files: ['cptra/build_mbedtls.sh', mbedtls_user_cfg],
      build_by_default: true)

    executable('aspeed_cptra', 'cptra/aspeed_cptra.c', mbedtls_make,
      install: true,
      include_directories: mbedtls_inc,
      c_args: ['-DMBEDTLS_USER_CONFIG_FILE="' + mbedtls_user_cfg + '"'])
  elif cptra_platform == 'ast2705'
    # Same target/output name as the ast2700 branch above -- exactly one
    # branch ever runs per configured build, so there's no name collision.
    executable('aspeed_cptra', 'cptra/aspeed_cptra_mci.c',
      install: true)
  endif
endif
