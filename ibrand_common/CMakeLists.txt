add_library(ibrand_common SHARED my_base64.c my_config.c my_filelock.c my_json.c my_logging.c my_utils.c)

set_target_properties(
  ibrand_common
  PROPERTIES
    SOVERSION 1.0
)

target_include_directories(ibrand_common PUBLIC ./)
