#!/usr/bin/env bash

PROJECT_NAME="remill"

main() {
  if [[ $# != 1 ]] ; then
    printf "Usage:\n\tgenerate_changelog.sh <path/to/changelog/file.md>\n"
    return 1
  fi

  local output_path="${1}"
  local current_version="$(git describe --tags --always)"
  local previous_version="$(git describe --tags --always --abbrev=0 ${current_version}^)"

  echo "Current version: ${current_version}"
  echo "Previous version: ${previous_version}"
  echo "Output file: ${output_path}"

  printf "# Changelog\n\n" > "${output_path}"
  printf "The following are the changes that happened between versions ${previous_version} and ${current_version}\n\n" >> "${output_path}"

  git log ${previous_version}...${current_version} \
    --pretty=format:" * [%h](http://github.com/lifting-bits/${PROJECT_NAME}/commit/%H) - %s" \
    --reverse | grep -v 'Merge branch' >> "${output_path}"

  return 0
}

main $@
exit $?
