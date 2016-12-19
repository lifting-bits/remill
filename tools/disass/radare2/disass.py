import CFG_pb2
try:
    import r2pipe
except:
    print("Install the radare2 python bindings. (https://github.com/radare/radare2-r2pipe)")

#
# It seems the proper way is to use 'program' API, but I was feeling
# confused on the purpose and source of some of the information to provide the calls.
# For example, is the Instruction personality field something I should be
# concerned with? It does not get translated to the generated protobuf stream,
# so my opinion is no. But, I do not fully get the IDA interface, so it
# is possible I am being very naive. 
# 
# So, first whack this way and then go from there... c'est la vie.


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

    mod = CFG_pb2.Module()
    for fne in fn_list:
        name = fne["name"]
        new_block = True

        # Having each function be a named block. Is enough?
        named_block = CFG_pb2.NamedBlock()
        named_block.name = name
        named_block.address = fne["offset"]
        named_block.visibility = 1	# XXX: Ehm; must revisit.
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
        for op in dis["ops"]:
            if new_block == True:
                print "new Block"
                if "bytes" not in op.keys():
                    print "Skipp"
                    continue
                blk = CFG_pb2.Block()
                blk.address = op["offset"]
                new_block = False
            else:
                print "old Block"
           
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
            btmp = [int(x, 16) for x in btmp]
            ii.bytes = ''.join(chr(x) for x in btmp)
            ii.address = op["offset"]    
            blk.instructions.extend([ii])
           
            # XXX: Unsure if want new block after a jump.
            # also, my jump check may be "too loose". 
            if op["opcode"].startswith("call") == True or \
               op["opcode"].startswith("ret") == True or \
               op["opcode"].startswith("j") == True:
                mod.blocks.extend([blk])
                new_block = True
                blk = None
                continue

    ostream = open(args.output, "wb")
    ostream.write(mod.SerializeToString())
    ostream.close()
    return 0
