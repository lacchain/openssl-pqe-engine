add_library(frodokem SHARED frodo640.c util.c aes/aes.c random/random.c sha3/fips202.c)

set_target_properties(
  frodokem 
  PROPERTIES
    SOVERSION 1.0
    COMPILE_FLAGS "-DNIX -D _AMD64_ -D _FAST_ -D _AES128_FOR_A_ -D _USE_OPENSSL_ -march=native -I/usr/include -mavx2 -maes -msse2"
)

target_include_directories(frodokem PUBLIC ./)
