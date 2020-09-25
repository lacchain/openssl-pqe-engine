include_directories(./Keccak ../../ibrand_common ../../ibrand_service)

pkg_search_module(FTDI REQUIRED libftdi)

add_library(ibrand_lib SHARED libibrand.c healthcheck.c writeentropy.c libibrand_get_new_entropy.c libibrand_config.c Keccak/KeccakF-1600-reference.c)

set_target_properties(
  ibrand_lib
  PROPERTIES
    SOVERSION 1.0
)

target_include_directories(ibrand_lib PUBLIC ./)
target_link_libraries(ibrand_lib PUBLIC ibrand_common)
target_link_libraries(ibrand_lib PUBLIC ibrand_service_shmem)
target_link_libraries(ibrand_lib PUBLIC ftdi)
target_link_libraries(ibrand_lib PUBLIC m)
