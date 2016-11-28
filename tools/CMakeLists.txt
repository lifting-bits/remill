# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

install(CODE
    "execute_process(COMMAND python ${PROJECT_SOURCE_DIR}/tools/setup.py install -f --prefix=${CMAKE_INSTALL_PREFIX})")
