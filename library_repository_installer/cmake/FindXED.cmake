set(LIBRARY_ROOT "${LIBRARY_REPOSITORY_ROOT}/xed")

set(XED_FOUND TRUE)
set(XED_INCLUDE_DIRS "${LIBRARY_ROOT}/include")

set(XED_LIBRARIES
    ${LIBRARY_ROOT}/lib/libxed.a
    ${LIBRARY_ROOT}/lib/libxed-ild.a
)

mark_as_advanced(FORCE XED_FOUND)
mark_as_advanced(FORCE XED_INCLUDE_DIRS)
mark_as_advanced(FORCE XED_LIBRARIES)

