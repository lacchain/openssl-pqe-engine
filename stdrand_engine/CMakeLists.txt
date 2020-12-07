add_library(stdrand_engine SHARED stdrand_engine.c)

target_link_libraries(stdrand_engine ibrand_common)

set_target_properties(
  stdrand_engine
  PROPERTIES
    SOVERSION 1.0
    PREFIX ""
)
