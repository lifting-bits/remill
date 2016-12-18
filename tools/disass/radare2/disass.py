
#
# The process I used in scripts was to:
#  radare $prog
#  > aa
#  > afl
# ... parse to make function list ...
#  for each $function:
#  > af@$function
#  > pdfj@$function
# ... handle the json output ...
# 
# Go through the json, put into protobuf form,
# and output the Module class you've made
# 
import json
import os
import subprocess
import sys
import tempfile
import traceback

def execute(args, command_args):

    radare2_disassembler = args.disassembler
    target_binary = args.binary

    r2script = tempfile.NamedTemporaryFile(delete=False)
    r2script.write("aa\r\nafl\r\n")
    r2script.close()
    cmd = []
    cmd.append(radare2_disassembler)
    cmd.append("-q")
    cmd.append("-i")
    cmd.append(r2script.name)
    cmd.append(target_binary)
    print("cmd: {}".format(" ".join(cmd)))
    # Each entry is { "name" : "....", "address" : }
    functions = []
    try:
        fn_list_raw = subprocess.check_output(cmd)
        print("RAW: {}".format(fn_list_raw))
        fn_list_raw = fn_list_raw.split("\n")
        for fe in fn_list_raw:
            fe = fe.split(" ")
            if fe[-1] != "" and fe[0] != "":
                functions.append({"name" : fe[-1], "address" : fe[0]})
                print("Adding {}, {}".format(fe[-1], fe[0]))
    except subprocess.CalledProcessError as e:
        sys.stderr.write(traceback.format_exc())
        return 1
    os.remove(r2script.name)

    r2script = tempfile.NamedTemporaryFile(delete=False)
    r2script.write("aa\r\n")
    for fentry in functions:
        r2script.write("af@{0}\r\npdfj@{0}\r\n".format(fentry["name"]))
    r2script.close()
    cmd = []
    cmd.append(radare2_disassembler)
    cmd.append("-q")
    cmd.append("-i")
    cmd.append(r2script.name)
    cmd.append(target_binary)
    fd_json = [] 
    try:
       fnd_json_raw = subprocess.check_output(cmd)
       fnd_json_raw = fnd_json_raw.split("\n")[0:-1]
       print fnd_json_raw
       fd_json = [json.loads(x) for x in fnd_json_raw]
    except subprocess.CalledProcessError as e:
       sys.stderr.write(traceback.format_exc())
       return 1
    os.remove(r2script.name)
    return 0
