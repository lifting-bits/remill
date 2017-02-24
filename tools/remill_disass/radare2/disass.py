
import log

import CFG_pb2
import x86

try:
    import r2pipe
except:
    print("Install the radare2 python bindings. (https://github.com/radare/radare2-r2pipe)")


def execute(args, command_args):
    log.init(output_file=args.log_file, log_level=args.log_level)


    target_arch = args.arch
    if target_arch != "x86":
        log.critical("Only x86 is currently supported.")
        return 1

    # This is really not used. r2pipe expects that
    # radare2 is in your $PATH.
    radare2_disassembler = args.disassembler

    mod = None

    r2 = r2pipe.open(args.binary, flags=["-a", target_arch])
    if target_arch == "x86":
        mod = x86.analyze(r2)

    if mod is None:
        return 1

    ostream = open(args.output, "wb")
    ostream.write(mod.SerializeToString())
    ostream.close()
    return 0
