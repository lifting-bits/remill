set(XED_FOUND TRUE)
set(XED_INCLUDE_DIRS
  "/repos/xed/include/public"
  "/repos/xed/obj/wkit/include/xed"
)
set(XED_LIBRARIES
  "/repos/xed/obj/libxed.a"
  "/repos/xed/obj/libxed-ild.a"
)
mark_as_advanced(FORCE XED_FOUND)
mark_as_advanced(FORCE XED_INCLUDE_DIRS)
mark_as_advanced(FORCE XED_LIBRARIES)