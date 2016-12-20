import CFG_pb2
import x86
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

    target_arch = args.arch
    if target_arch != "x86":
        print("Only x86 is currently supported.")
        return 1

    # This is really not used. r2pipe expects that
    # radare2 is in your $PATH.
    radare2_disassembler = args.disassembler

    mod = None

    r2 = r2pipe.open(args.binary, flags=["-a", target_arch])
    r2.cmd("aa") # ``Analyze all''
    if target_arch == "x86":
        mod = x86.analyze(r2)

    if mod is None:
        return 1

    ostream = open(args.output, "wb")
    ostream.write(mod.SerializeToString())
    ostream.close()
    return 0
