cmake_minimum_required(VERSION 3.10)

project(IB_OPENSSL_ENGINE VERSION 1.0 LANGUAGES C)

find_package(PkgConfig REQUIRED)
include(GNUInstallDirs)

add_subdirectory(ibrand_common)
add_subdirectory(ibrand_lib)
add_subdirectory(ibrand_service)
add_subdirectory(ibrand_engine)
add_subdirectory(ibinit_engine)

pkg_get_variable(OPENSSL_ENGINES_DIR libcrypto enginesdir)
pkg_get_variable(OPENSSL_PREFIX      libcrypto prefix)
string(REPLACE "${OPENSSL_PREFIX}/" "" OPENSSL_ENGINES_DESTINATION "${OPENSSL_ENGINES_DIR}")

install ( TARGETS ibrand_common        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}        )
install ( TARGETS ibrand_lib           LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}        )
install ( TARGETS ibrand_service_shmem LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}        )
install ( TARGETS ibrand_service       RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}        )
install ( TARGETS ibrand_engine        LIBRARY DESTINATION ${OPENSSL_ENGINES_DESTINATION} )
install ( TARGETS ibinit_engine       LIBRARY DESTINATION ${OPENSSL_ENGINES_DESTINATION} )
