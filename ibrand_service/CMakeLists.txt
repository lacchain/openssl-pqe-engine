find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(ibrand_service_shmem SHARED ibrand_service_shmem.c)
set_target_properties(
  ibrand_service_shmem
  PROPERTIES
    SOVERSION 1.0
)
target_link_libraries(ibrand_service_shmem ibrand_common)
target_link_libraries(ibrand_service_shmem rt)

add_executable(ibrand_service ibrand_service.c ibrand_service_config.c ibrand_service_utils.c ibrand_service_datastore.c ibrand_service_aes.c RFC2898DeriveBytes.c)

target_link_libraries(ibrand_service ibrand_service_shmem)
target_link_libraries(ibrand_service ibrand_common)
target_link_libraries(ibrand_service frodokem)
target_link_libraries(ibrand_service ${CURL_LIBRARIES})
target_link_libraries(ibrand_service ${OPENSSL_LIBRARIES})
target_link_libraries(ibrand_service ${CMAKE_THREAD_LIBS_INIT})
