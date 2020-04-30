# - Try to find Hiredis
# Once done this will define
#
#  HIREDIS_FOUND - system has HIREDIS
#  HIREDIS_INCLUDE_DIR - the HIREDIS include directory
#  HIREDIS_LIBRARY - Link these to use HIREDIS

if (HIREDIS_INCLUDE_DIR)
  # Already in cache, be silent
  set(HIREDIS_FIND_QUIETLY TRUE)
ENDif (HIREDIS_INCLUDE_DIR)

find_path(
    HIREDIS_INCLUDE_DIR hiredis.h
    /usr/local/include/hiredis
    /usr/include/hiredis
)
set(HIREDIS_NAMES hiredis hiredis.h hiredis/hiredis.h)
find_library(
    HIREDIS_LIBRARY
    NAMES hiredis libhiredis
    DOC "hiredis library"
    PATHS /usr/lib /usr/local/lib
    PATH_SUFFIXES hiredis
)

set(HIREDIS_INCLUDE_DIRS ${HIREDIS_INCLUDE_DIR})
set(HIREDIS_LIBRARIES ${HIREDIS_LIBRARY})

if (HIREDIS_INCLUDE_DIR AND HIREDIS_LIBRARY)
  set(HIREDIS_FOUND TRUE)
  set( HIREDIS_LIBRARIES ${HIREDIS_LIBRARY} )
else (HIREDIS_INCLUDE_DIR AND HIREDIS_LIBRARY)
  set(HIREDIS_FOUND FALSE)
  set( HIREDIS_LIBRARIES )
endif (HIREDIS_INCLUDE_DIR AND HIREDIS_LIBRARY)

if (HIREDIS_FOUND)
  if (NOT HIREDIS_FIND_QUIETLY)
    message(STATUS "Found HIREDIS: ${HIREDIS_LIBRARY}")
  endif (NOT HIREDIS_FIND_QUIETLY)
else (HIREDIS_FOUND)
  if (HIREDIS_FIND_REQUIRED)
    message(STATUS "Looked for HIREDIS libraries named ${HIREDIS_NAMES}.")
    message(FATAL_ERROR "Could NOT find HIREDIS library")
  endif (HIREDIS_FIND_REQUIRED)
endif (HIREDIS_FOUND)

mark_as_advances(
  HIREDIS_LIBRARY
  HIREDIS_INCLUDE_DIR
  )
