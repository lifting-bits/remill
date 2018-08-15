/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace remill {

bool TryCreateDirectory(const std::string &dir_name);

using DirectoryVisitor = std::function<bool(const std::string &path)>;

// Iterator over a directory.
void ForEachFileInDirectory(const std::string &dir_name,
                            DirectoryVisitor visitor);

std::string CurrentWorkingDirectory(void);

bool FileExists(const std::string &path);

uint64_t FileSize(int fd);
uint64_t FileSize(const std::string &path, int fd);
uint64_t FileSize(const std::string &path);

void RemoveFile(const std::string &path);
bool RenameFile(const std::string &from_path, const std::string &to_path);
void HardLinkOrCopyFile(const std::string &from_path,
                        const std::string &to_path);
void CopyFile(const std::string &from_path, const std::string &to_path);
void MoveFile(const std::string &from_path, const std::string &to_path);

// Returns a canonical path name for `path` (calls `realpath`).
std::string CanonicalPath(const std::string &path);

// Returns the path separator character for this OS.
const char *PathSeparator(void);

}  // namespace remill
