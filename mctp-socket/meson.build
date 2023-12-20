project('mctp-socket-based-utilities', 'c', 'cpp',
        version : '1.0',
        meson_version: '>=0.57.0',
        default_options: [
            'werror=true',
           ])

# Generate the aspeed-pfr-tool executable
executable(
    'mctp-skt-req',
    [
      'mctp-req.c',
      'mctp-util.c'
    ],
    install: true
)

executable(
    'mctp-skt-recv',
    [
      'mctp-recv.c'
    ],
    install: true
)

