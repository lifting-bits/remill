
import json
import os
import subprocess
import sys
import tempfile
import traceback

try:
    import r2pipe
except:
    print("Install the radare2 python bindings. (https://github.com/radare/radare2-r2pipe)")


def execute(args, command_args):
    # This is really not used. r2pipe expects that
    # radare2 is in your $PATH.
    radare2_disassembler = args.disassembler

    r2 = r2pipe.open(args.binary)

    # Analyze all
    r2.cmd("aa")

    # Get list of json dicts that have function information.
    # An entry in the list is like:
    # {
    #   "offset":4196100,
    #   "name":"sym._fini",
    #   "size":9,
    #   "realsz":9,
    #   "cc":1,
    #   "nbbs":1,
    #   "edges":0,
    #   "ebbs":1,
    #   "calltype":"amd64",
    #   "type":"sym",
    #   "diff":"NEW",
    #   "callrefs":[{ "address":"", "type" : "", "at" : ""},...],
    #   "datarefs":[NNN, NNN...],
    #   "codexrefs":[],
    #   "dataxrefs":[],
    #   "difftype":"new",
    #   "indegree":0,
    #   "outdegree":0,
    #   "nargs":0,
    #   "nlocals":0
    # }
    fn_list = r2.cmdj("aflj")
    for fne in fn_list:
        name = fne["name"]

        # Analyze the current function
        r2.cmd("af@{0}".format(name))

        # Disassemble function and return in json, which 
        # will look like:
        # {
        #   "name":"sym.main",
        #   "size":261,
        #   "addr":4195709,
        #   "ops": [
        #      {
        #        "offset":4195709,
        #        "esil":"rbp,8,rsp,-=,rsp,=[8]",
        #        "refptr":false,
        #        "fcn_addr":4195709,
        #        "fcn_last":4195969,
        #        "size":1,
        #        "opcode":"push rbp",
        #        "bytes":"55",
        #        "family":"cpu",
        #        "type":"upush",
        #        "type_num":12,
        #        "type2_num":0,
        #        "flags":["main","sym.main"],
        #        "xrefs":[{"addr":4195501,"type":"DATA"}]
        #      }, ... ]
        # }
        dis = r2.cmdj("pdfj@{0}".format(name))
   
    return 0
