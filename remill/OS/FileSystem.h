/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_OS_FILESYSTEM_H_
#define REMILL_OS_FILESYSTEM_H_

#include <cstdint>
#include <string>

namespace remill {

bool TryCreateDirectory(const std::string &dir_name);

std::string CurrentWorkingDirectory(void);

bool FileExists(const std::string &path);

uint64_t FileSize(const std::string &path, int fd);
uint64_t FileSize(const std::string &path);

void RemoveFile(const std::string &path);
void RenameFile(const std::string &from_path, const std::string &to_path);
void HardLinkOrCopy(const std::string &from_path, const std::string &to_path);

}  // namespace remill

#endif  // REMILL_OS_FILESYSTEM_H_
