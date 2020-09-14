add_library(ibrand_openssl SHARED e_ibrand.c)

set_target_properties(
  ibrand_openssl
  PROPERTIES
    SOVERSION 1.0
    PREFIX ""
)

target_link_libraries(ibrand_openssl PUBLIC ibrand_lib)

