# Sleigh patches

The [sleigh](https://github.com/lifting-bits/sleigh) repository uses `git am` to apply a list of patches to a specific Ghidra base commit. These patches are mostly to make Ghidra's decompiler source code reusable as a library and suitable for packaging. You can find more information in [sleigh/src/README.md](https://github.com/lifting-bits/sleigh/blob/master/src/README.md).

Remill has a bunch of additional patches, which improve the semantics themselves (sleigh files). These are applied on top of the sleigh patches and specified in `sleigh_ADDITIONAL_PATCHES`.

To update the patches or the sleigh base commit, we need to get a cloned Ghidra source tree that only has the sleigh patches applied. From there we will apply the patches in this repository manually and recreate the patch folder.

1. Go in `build/_deps/ghidrasource-src` and run `git status` to make sure you are in a clean state. You might need to run `git am --abort` to abort the patching process if you had patch failures.
2. Modify remill's `CMakeLists.txt` to set `sleigh_ADDITIONAL_PATCHES` to be empty and re-configure remill. This will apply just the patches of the sleigh project's tag we pinned.
3. Get the commit hash of the clean Ghidra patches with `git rev-parse HEAD` and note it as `<base-commit>`.
4. Apply the patches in `patches/sleigh/` one by one with `git am ../../../patches/sleigh/0001-xyz.patch`. If you get any errors, manually apply the patch (you can try `git apply ../../../patches/sleigh/0001-xyz.patch`) and then `git add .` followed by `git am --continue`. The goal is to create a commit for every patch.
5. Delete all the old patches: `rm patches/sleigh/*.patch`.
6. Recreate the patch list: `git format-patch remill-sleigh-7c6b742-base -o ../../../patches/sleigh/`.
7. Reconfigure remill's CMake to make sure everything applies correctly and then change `sleigh_ADDITIONAL_PATCHES` batch to include all of the patches in `patches/sleigh/`.

**Note**: Sometimes you run into issues where `git am` cannot correctly apply all the patches. This is usually related to whitespace issues. Before exporting the patch list you can run `git rebase <base-commit> --whitespace=fix` to make sure everything is cleaned up correctly and ready to be applied.
