# Try to find the liboqs library and headers
# Sets the following variables:
#   LIBOQS_FOUND
#   LIBOQS_INCLUDE_DIRS
#   LIBOQS_LIBRARIES

find_path(LIBOQS_INCLUDE_DIR
    NAMES oqs/oqs.h
    PATH_SUFFIXES include
)

find_library(LIBOQS_LIBRARY
    NAMES oqs liboqs
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(liboqs
    REQUIRED_VARS LIBOQS_INCLUDE_DIR LIBOQS_LIBRARY
)

if(LIBOQS_FOUND)
    set(LIBOQS_INCLUDE_DIRS ${LIBOQS_INCLUDE_DIR})
    set(LIBOQS_LIBRARIES ${LIBOQS_LIBRARY})
endif()

