### Trail of Bits common library

The `build.sh` script fetches and installs common libraries needed by several Trail of Bits projects, including Remill and McSema. The CMake files will export all settings automatically to any target linking to remill.

#### Usage

```shell
./build.sh /where/to/put/libraries
```

*Note:* The last path component of the target directory _must_ be `libraries`.