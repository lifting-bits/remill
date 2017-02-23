import json
import log

import CFG_pb2
try:
    import r2pipe
except:
    log.critical("Install the radare2 python bindings. (https://github.com/radare/radare2-r2pipe)")

#
# I have concerns on performance in large executable scenarios.
# I do not have faith.. Qapla'
#


#
# r2 is a r2pipe.open instance
#
def analyze(r2):

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

    #
    # The purpose of running these is to get the executable
    # analyzed so the representation given from radare2 is 
    # in a form that is useful to being remill-ingested.
    # I am sure there are improvements to be made here.
    #
    # Should investigate using:
    #   aaaa is experimental
    log.warning("Fuck you")
    prep_analyses = {
      "aa" : "alias for 'af@@ sym.*;af@entry0;afva'",
      "aaa" : " autoname functions after aa (see afna)",
      "aab" : "analyze blocks over text section",
      "aac" : "analyze function calls",
      "aad" : "analyze data references to code",
      "aae" : "analyze references with ESIL",
      "aap" : "analyze function preludes"
    }
    for x,y in prep_analyses.iteritems():
        log.info("running command for: {}".format(y))
        r2.cmd(x)
    
    fn_list = r2.cmdj("aflj")

    mod = CFG_pb2.Module()
    for fne in fn_list:
        name = fne["name"]
        new_block = True

        # Having each function be a named block. Is enough?
        named_block = CFG_pb2.NamedBlock()
        named_block.name = name
        named_block.address = fne["offset"]

        # XXX: I am a bit confused on the meaning of the 1 and 0 for
        # visibility. I am setting the imported symbols to visibility 1.
        if name.startswith("sym.imp.") == True:
            named_block.visibility = 1
        else:
            named_block.visibility = 0
        mod.named_blocks.extend([named_block])

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
        if dis is None:
            log.warning("Unable to disassemble {0}".format(name))
            continue

        for op in dis["ops"]:
            if new_block == True:
                if "bytes" not in op.keys():
                    continue
                blk = CFG_pb2.Block()
                blk.address = op["offset"]
                new_block = False
           
            if "bytes" not in op.keys():
                if new_block == False:
                    mod.blocks.extend([blk])
                    new_block = True
                    blk = None
                continue

            ii = CFG_pb2.Instr()

            # I was using python3 before so had bytes.fromhex() API call,
            # but I believe this is the correct juju for Python2
            btmp = [op["bytes"][i:i+2] for i in range(0, len(op["bytes"]), 2)]
            ii.bytes = ''.join([chr(int(x, 16)) for x in btmp])
            ii.address = op["offset"]    
            oc = op["opcode"]

            #
            # Unsure if this is the behavior that is desired
            # further, perhaps the json dumping should be a verbose option.
            if oc.startswith("ud2") == True:
                log.warning("Undefined (ud2) {1}@{0}. Ignoring block, skipping to next function! ".format(op["offset"], name))
                log.debug("Disassembling function: {}".format(name))
                log.debug("{}".format(json.dumps(dis, sort_keys=False, indent=4, separators=(",", ": "))))
                new_block = True
                blk = None
                break

            blk.instructions.extend([ii])
            blk_terminators = ["call", "ret", "int", "j", "iret", "hlt", "nop", \
              "lcall", "ljmp", "syscall" ]
            for bt in blk_terminators: 
                if oc.startswith(bt) == True:
                    mod.blocks.extend([blk])
                    new_block = True
                    blk = None
                    break
        if blk:
            log.warning("Reach non-block terminated set of instructions... inserting block anyway")
            mod.blocks.extend([blk])

    return mod
