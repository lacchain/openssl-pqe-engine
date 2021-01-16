include_directories(../ibrand_common ../ibrand_service)

add_library(ibrand_engine SHARED ibrand_engine.c ibrand_main.c writeentropy.c ibrand_get_new_entropy.c ibrand_config.c)

set_target_properties(
  ibrand_engine
  PROPERTIES
    SOVERSION 1.0
    PREFIX ""
)

target_link_libraries(ibrand_engine PUBLIC ibrand_common)
target_link_libraries(ibrand_engine PUBLIC ibrand_service_shmem)
target_link_libraries(ibrand_engine PUBLIC m)
