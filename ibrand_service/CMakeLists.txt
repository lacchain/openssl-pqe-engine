#pkg_search_module(FTDI REQUIRED libftdi)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(ibrand_service ibrand_service.c IB_SymmetricEncryption.c RFC2898DeriveBytes.c)

target_link_libraries(ibrand_service ibrand_common)
target_link_libraries(ibrand_service frodokem)
target_link_libraries(ibrand_service ${CURL_LIBRARIES})
target_link_libraries(ibrand_service ${OPENSSL_LIBRARIES})
