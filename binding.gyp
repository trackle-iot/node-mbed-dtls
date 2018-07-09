{
  "targets": [
    {
      "target_name": "mbedtls",
      "type": "static_library",
      "sources": [
        "mbedtls/library/debug.c",
        "mbedtls/library/net.c",
        "mbedtls/library/ssl_cache.c",
        "mbedtls/library/ssl_ciphersuites.c",
        "mbedtls/library/ssl_cli.c",
        "mbedtls/library/ssl_cookie.c",
        "mbedtls/library/ssl_srv.c",
        "mbedtls/library/ssl_ticket.c",
        "mbedtls/library/ssl_tls.c"
      ],
      "include_dirs": [
        "mbedtls/include",
        "config"
      ],
      "defines": [
        "MBEDTLS_CONFIG_FILE=\"mbedtls_config.h\""
      ]
    },
    {
      "target_name": "mbedx509",
      "type": "static_library",
      "sources": [
        "mbedtls/library/certs.c",
        "mbedtls/library/pkcs11.c",
        "mbedtls/library/x509.c",
        "mbedtls/library/x509_create.c",
        "mbedtls/library/x509_crl.c",
        "mbedtls/library/x509_crt.c",
        "mbedtls/library/x509_csr.c",
        "mbedtls/library/x509write_crt.c",
        "mbedtls/library/x509write_csr.c"
      ],
      "include_dirs": [
        "mbedtls/include",
        "config"
      ],
      "defines": [
        "MBEDTLS_CONFIG_FILE=\"mbedtls_config.h\""
      ]
    },
    {
      "target_name": "mbedcrypto",
      "type": "static_library",
      "sources": [
        "mbedtls/library/aes.c",
        "mbedtls/library/aesni.c",
        "mbedtls/library/arc4.c",
        "mbedtls/library/asn1parse.c",
        "mbedtls/library/asn1write.c",
        "mbedtls/library/base64.c",
        "mbedtls/library/bignum.c",
        "mbedtls/library/blowfish.c",
        "mbedtls/library/camellia.c",
        "mbedtls/library/ccm.c",
        "mbedtls/library/cipher.c",
        "mbedtls/library/cipher_wrap.c",
        "mbedtls/library/ctr_drbg.c",
        "mbedtls/library/des.c",
        "mbedtls/library/dhm.c",
        "mbedtls/library/ecdh.c",
        "mbedtls/library/ecdsa.c",
        "mbedtls/library/ecp.c",
        "mbedtls/library/ecp_curves.c",
        "mbedtls/library/entropy.c",
        "mbedtls/library/entropy_poll.c",
        "mbedtls/library/error.c",
        "mbedtls/library/gcm.c",
        "mbedtls/library/havege.c",
        "mbedtls/library/hmac_drbg.c",
        "mbedtls/library/md.c",
        "mbedtls/library/md2.c",
        "mbedtls/library/md4.c",
        "mbedtls/library/md5.c",
        "mbedtls/library/md_wrap.c",
        "mbedtls/library/memory_buffer_alloc.c",
        "mbedtls/library/oid.c",
        "mbedtls/library/padlock.c",
        "mbedtls/library/pem.c",
        "mbedtls/library/pk.c",
        "mbedtls/library/pk_wrap.c",
        "mbedtls/library/pkcs12.c",
        "mbedtls/library/pkcs5.c",
        "mbedtls/library/pkparse.c",
        "mbedtls/library/pkwrite.c",
        "mbedtls/library/platform.c",
        "mbedtls/library/ripemd160.c",
        "mbedtls/library/rsa.c",
        "mbedtls/library/sha1.c",
        "mbedtls/library/sha256.c",
        "mbedtls/library/sha512.c",
        "mbedtls/library/threading.c",
        "mbedtls/library/timing.c",
        "mbedtls/library/version.c",
        "mbedtls/library/version_features.c",
        "mbedtls/library/xtea.c"
      ],
      "include_dirs": [
        "mbedtls/include",
        "config"
      ],
      "defines": [
        "MBEDTLS_CONFIG_FILE=\"mbedtls_config.h\""
      ]
    },
    {
      "target_name": "mbedjpake",
      "type": "static_library",
      "sources": [
        "mbedtls/library/ecjpake.c"
      ],
      "include_dirs": [
        "mbedtls/include",
        "config"
      ],
      "defines": [
        "MBEDTLS_CONFIG_FILE=\"mbedtls_config.h\""
      ]
    },
    {
      "target_name": "node_mbed_dtls",
      "sources": [
        "src/init.cc",
        "src/Util.cc",
        "src/MbedTlsError.cc",
        "src/Drbg.cc",
        "src/DtlsServer.cc",
        "src/DtlsSocket.cc",
        "src/SessionWrap.cc",
        "src/EcjPake.cc"
      ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
        "mbedtls/include",
        "config"
      ],
      "dependencies": [
        "mbedtls",
        "mbedx509",
        "mbedcrypto",
        "mbedjpake"
      ],
      'cflags_cc': [ '-std=c++11' ],
      # Make sure exceptions and RTTI are enabled
      'cflags_cc!': [ '-fno-exceptions', '-fno-rtti' ],
      # MacOS requires some special treatment
      'xcode_settings': {
        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
        'GCC_ENABLE_CPP_RTTI': 'YES',
        'OTHER_CFLAGS': [
          '-std=c++11',
          '-stdlib=libc++'
        ]
      },
      "defines": [
        "MBEDTLS_CONFIG_FILE=\"mbedtls_config.h\""
      ]
    },
  ]
}
