# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

import logging
import sys


_LOGGER = None


def init(output_stream=None):
  global _LOGGER
  assert not _LOGGER
  if isinstance(output_stream, str):
    output_stream = open(output_stream, "w")

  _LOGGER = logging.getLogger("cfg")
  formatter = logging.Formatter("%(levelname)s: %(message)s")
  handler = logging.StreamHandler(output_stream or sys.stderr)
  handler.setFormatter(formatter)
  _LOGGER.addHandler(handler)
  _LOGGER.setLevel(logging.DEBUG)


def debug(*args, **kargs):
  global _LOGGER
  _LOGGER.debug(*args, **kargs)


def info(*args, **kargs):
  global _LOGGER
  _LOGGER.info(*args, **kargs)


def warning(*args, **kargs):
  global _LOGGER
  _LOGGER.warning(*args, **kargs)


def error(*args, **kargs):
  global _LOGGER
  _LOGGER.error(*args, **kargs)
