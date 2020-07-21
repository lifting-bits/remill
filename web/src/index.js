#!/usr/bin/env node
const remill = require("./remill-lift-10.0.js");
console.log(
    "Using Emscripten's virtual file system instead of node fs, " +
    "writing a file to /out will be printed, e.g. ir_out=/out");
remill.onRuntimeInitialized = () => {
    remill.callMain(process.argv.slice(2));
    try {
        console.log(remill.FS.readFile('/out', { encoding: 'utf8' }))
    } catch (err) {
    }
}