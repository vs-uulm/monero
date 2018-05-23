# - Find PCSC
# Find the native PCSC includes and library
#
#  PCSC_INCLUDE_DIR - where to find winscard.h, wintypes.h, etc.
#  PCSC_LIBRARIES   - List of libraries when using PCSC.
#  PCSC_FOUND       - True if PCSC found.


IF (PCSC_INCLUDE_DIR AND PCSC_LIBRARIES)
  # Already in cache, be silent
  SET(PCSC_FIND_QUIETLY TRUE)
ENDIF (PCSC_INCLUDE_DIR AND PCSC_LIBRARIES)

IF (NOT WIN32)
  FIND_PACKAGE(PkgConfig)
  PKG_CHECK_MODULES(PC_PCSC libpcsclite)
ENDIF (NOT WIN32)

FIND_PATH(PCSC_INCLUDE_DIR winscard.h
  HINTS
  IF (WIN32)
  ${MSYS2_FOLDER}/mingw64/x86_64-w64-mingw32/include
  ENDIF (WIN32)
  /usr/include/PCSC
  ${PC_PCSC_INCLUDEDIR}
  ${PC_PCSC_INCLUDE_DIRS}
  PATH_SUFFIXES PCSC
  )

FIND_LIBRARY(PCSC_LIBRARY NAMES pcsclite libpcsclite WinSCard PCSC
  HINTS
  IF (WIN32)
  ${MSYS2_FOLDER}/mingw64/x86_64-w64-mingw32/lib
  ENDIF (WIN32)
  ${PC_PCSC_LIBDIR}
  ${PC_PCSC_LIBRARY_DIRS}
  )

# handle the QUIETLY and REQUIRED arguments and set PCSC_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PCSC DEFAULT_MSG PCSC_LIBRARY PCSC_INCLUDE_DIR)

IF(PCSC_FOUND)
  SET( PCSC_LIBRARIES ${PCSC_LIBRARY} )
ELSE(PCSC_FOUND)
  SET( PCSC_LIBRARIES )
ENDIF(PCSC_FOUND)

MARK_AS_ADVANCED( PCSC_LIBRARY PCSC_INCLUDE_DIR )
