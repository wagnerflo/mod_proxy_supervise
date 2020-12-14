cmake_minimum_required( VERSION 3.14 )
project ( mod_proxy_supervise )

# find required packages and libraries
# find_package( PkgConfig REQUIRED )
# pkg_check_modules( APR1      REQUIRED IMPORTED_TARGET apr-1 )

find_program( APXS apxs DOC "Apache/HTTPD extension tool location" )
if( NOT APXS )
  message( FATAL_ERROR
    "Could not find apxs - make sure the apache/httpd dev package is installed"
  )
endif()

execute_process( COMMAND ${APXS} -q exp_includedir
  OUTPUT_VARIABLE HTTPD_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE )
execute_process( COMMAND ${APXS} -q CFLAGS
  OUTPUT_VARIABLE HTTPD_CFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE )
execute_process( COMMAND ${APXS} -q APR_INCLUDEDIR
  OUTPUT_VARIABLE APR_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE )

add_library( ${PROJECT_NAME} SHARED
  src/entry.c
  src/handler.c
  src/init.c
)
set_target_properties( ${PROJECT_NAME} PROPERTIES
  PREFIX ""
)
target_include_directories( ${PROJECT_NAME} PRIVATE
  ${HTTPD_INCLUDE_DIR}
  ${APR_INCLUDE_DIR}
  ../libs7e/include
)
target_link_directories( ${PROJECT_NAME} PRIVATE
  ../libs7e
)
target_compile_options( ${PROJECT_NAME} PRIVATE
  SHELL:${HTTPD_CFLAGS}
)
target_link_libraries( ${PROJECT_NAME}
  s7e
)
