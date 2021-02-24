include_directories(../ibrand_common)

add_library(ibinit_engine SHARED ibinit_engine.c)

set_target_properties(
  ibinit_engine
  PROPERTIES
    SOVERSION 1.0
    PREFIX ""
)
target_link_libraries(ibinit_engine PUBLIC ibrand_common)
