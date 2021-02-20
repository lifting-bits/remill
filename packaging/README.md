# remill packaging scripts

## How to generate packages

1. Configure and build remill
2. Set the **DESTDIR** variable to a new folder
3. Run the packaging script, passing the **DESTDIR** folder

Example:

```sh
remill_version=$(git describe --always)

cpack -D REMILL_DATA_PATH="/path/to/install/directory" \
      -R ${remill_version} \
      --config "packaging/main.cmake"
```
