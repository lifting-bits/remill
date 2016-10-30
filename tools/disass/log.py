# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

import logging
import sys


_LOGGER = None


_LOG_LEVEL = {
  0: logging.DEBUG,
  1: logging.INFO,
  2: logging.WARNING,
  3: logging.ERROR,
  4: logging.CRITICAL
}


def init(output_file=None, output_stream=None, log_level=2):
  global _LOGGER, _LOG_LEVEL

  assert not _LOGGER
  if output_file:
    assert not output_stream
    output_stream = open(output_file, "w")

  _LOGGER = logging.getLogger("cfg")
  formatter = logging.Formatter("%(levelname)s: %(message)s")
  handler = logging.StreamHandler(output_stream or sys.stderr)
  handler.setFormatter(formatter)
  _LOGGER.addHandler(handler)
  _LOGGER.setLevel(_LOG_LEVEL[log_level])


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

