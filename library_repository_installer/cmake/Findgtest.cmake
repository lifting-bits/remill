set(LIBRARY_ROOT "${LIBRARY_REPOSITORY_ROOT}/googletest")

set(gtest_FOUND TRUE)
set(gtest_INCLUDE_DIRS "${LIBRARY_ROOT}/include")

set(gtest_LIBRARIES
    ${LIBRARY_ROOT}/lib/libgtest.a
)

mark_as_advanced(FORCE gtest_FOUND)
mark_as_advanced(FORCE gtest_INCLUDE_DIRS)
mark_as_advanced(FORCE gtest_LIBRARIES)

