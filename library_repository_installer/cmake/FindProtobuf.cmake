set(LIBRARY_ROOT "${LIBRARY_REPOSITORY_ROOT}/protobuf")

set(Protobuf_FOUND TRUE)
set(Protobuf_INCLUDE_DIR "${LIBRARY_ROOT}/include")
set(Protobuf_PROTOC_EXECUTABLE "${LIBRARY_ROOT}/bin/protoc")
set(Protobuf_LIBRARIES ${LIBRARY_ROOT}/lib/libprotobuf.a)
set(Protobuf_PROTOC_LIBRARIES ${LIBRARY_ROOT}/lib/libprotoc.a)

mark_as_advanced(FORCE Protobuf_FOUND)
mark_as_advanced(FORCE Protobuf_INCLUDE_DIR)
mark_as_advanced(FORCE Protobuf_PROTOC_EXECUTABLE)
mark_as_advanced(FORCE Protobuf_LIBRARIES)
mark_as_advanced(FORCE Protobuf_PROTOC_LIBRARIES)

