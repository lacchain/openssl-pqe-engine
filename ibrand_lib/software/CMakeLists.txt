include_directories(../../ibrand_common ../../ibrand_service)

add_library(ibrand_lib SHARED libibrand.c writeentropy.c libibrand_get_new_entropy.c libibrand_config.c)

set_target_properties(
  ibrand_lib
  PROPERTIES
    SOVERSION 1.0
)

target_include_directories(ibrand_lib PUBLIC ./)
target_link_libraries(ibrand_lib PUBLIC ibrand_common)
target_link_libraries(ibrand_lib PUBLIC ibrand_service_shmem)
target_link_libraries(ibrand_lib PUBLIC m)
