import argparse
import re
from typing import Dict, List, Match, Optional, Set, Tuple
from pathlib import Path
import os
import subprocess
import abc
from sortedcontainers import SortedSet

CONNECTIVES_WITHOUT_SEMICOLON = "&|.!"
CONNECTIVES = CONNECTIVES_WITHOUT_SEMICOLON+r";"

OPERATORS = r"*\-+\>\<\(\)$"

PCODE_SPECIFIC_OPERATORS = r"\[\]:=\#,'"

GENERIC_CHARACTER_GROUP_WITH_EQUALS = r"["+CONNECTIVES + OPERATORS+r"\w\s\d=]"

GENERIC_CHARACTER_GROUP_WITHOUT_EQUALS = r"[" + \
    CONNECTIVES + OPERATORS+r"\w\s\d]"

DISPLAY_SECTION = r"(?P<display_section>[][\"+*\w\s^,.]*)(?:[\s]is[\s])"


DISASSEMBLY_ACTION = r"(?P<action>"+GENERIC_CHARACTER_GROUP_WITH_EQUALS + "+" + \
    "="+GENERIC_CHARACTER_GROUP_WITH_EQUALS + r"+;[\s]*)"

DISASSEMBLY_ACTION_SECTION = r"(?P<action_section>\[" + \
    DISASSEMBLY_ACTION + r"*\])"

SEMANTICS_STATEMENT = "(?P<statement>[\s\w" + \
    PCODE_SPECIFIC_OPERATORS+OPERATORS+CONNECTIVES_WITHOUT_SEMICOLON+"+]*;)"

SEMANTICS_SECTION = r"\s*(?P<complete_semantics_section>[{]\s*(?P<semantics>\s" + \
    SEMANTICS_STATEMENT+r"*\s*)\s*[}])\s*"

CONSTRUCTOR_BASE_REGEX = r"(?P<table_name>[\w]*):" + DISPLAY_SECTION + \
    GENERIC_CHARACTER_GROUP_WITH_EQUALS + r"*" + \
    DISASSEMBLY_ACTION_SECTION + r"?" + SEMANTICS_SECTION

CONTEXTREG_STATEMENT = r"(?P<context_reg_definition>define\s+context\s+contextreg(?:[^;])*;)"


class Context:
    def __init__(self) -> None:
        self.name_ctr = 0


REMILL_INSN_SIZE_NAME = "remill_insn_size"


class ExpressionReplacer(abc.ABC):
    def __init__(self) -> None:
        self.program_counter = "$(INST_NEXT_PTR)"
        super().__init__()

    @abc.abstractmethod
    def applies_to_expression(self, exp: str) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def generate_unfolded_exp(self, exp: str) -> str:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def required_invisible_operands(self) -> List[str]:
        raise NotImplementedError


class InstStartReplacer(ExpressionReplacer):
    def __init__(self) -> None:
        super().__init__()

    def applies_to_expression(self, exp: str) -> bool:
        return "inst_start" in exp

    def generate_unfolded_exp(self, exp: str) -> str:
        return exp.replace("inst_start", f"({self.program_counter}-{REMILL_INSN_SIZE_NAME})")

    @property
    def required_invisible_operands(self) -> List[str]:
        return [REMILL_INSN_SIZE_NAME]


class InstNextReplacer(ExpressionReplacer):
    def __init__(self) -> None:
        super().__init__()

    def applies_to_expression(self, exp: str) -> bool:
        return "inst_next" in exp

    def generate_unfolded_exp(self, exp: str) -> str:
        return exp.replace("inst_next", self.program_counter)

    @property
    def required_invisible_operands(self) -> List[str]:
        return [REMILL_INSN_SIZE_NAME]


class Environment:
    def __init__(self, cont: Context, size_hint: str, replacements: List[ExpressionReplacer]) -> None:
        self.name_to_invisible_variables: Dict[str, Set[str]] = {}
        self.names_to_calculating_expression: Dict[str, str] = {}
        self.definition_statements: Dict[str, str] = {}
        self.cont = cont
        self.size_hint = size_hint
        self.replacements = replacements
        self.op_replacements = {"$and": "&", "$or": "|", "$xor": "^"}
        self.handle_inst_next_statement("inst_next=inst_next")
        self.handle_inst_next_statement("inst_start=inst_start")

    def prepare_statement(self, repl: ExpressionReplacer,  name: str, exp: str):
        replaced_exp = repl.generate_unfolded_exp(exp)
        for k, v in self.op_replacements.items():
            replaced_exp = replaced_exp.replace(k, v)
        if name not in self.names_to_calculating_expression:
            for k in repl.required_invisible_operands:
                self.name_to_invisible_variables.setdefault(name, set()).add(k)
            self.cont.name_ctr += 1
            definer = f"remill_please_dont_use_this_temp_name{self.cont.name_ctr:x}:{self.size_hint}={name}"
            claim = f"claim_eq(remill_please_dont_use_this_temp_name{self.cont.name_ctr:x}, {replaced_exp})"
            self.names_to_calculating_expression[name] = claim
            self.definition_statements[name] = definer

    def get_required_invisible_operands(self, statements: List[str]) -> List[str]:
        tot_reqs = set()
        for (expr_name, action_name) in self.name_to_invisible_variables.items():
            for stat in statements:
                if expr_name in stat:
                    tot_reqs.update(action_name)

        return list(tot_reqs)

    def get_priors(self, stat: str) -> List[str]:
        tot = []
        to_remove = []
        for k, v in self.definition_statements.items():
            if k in stat:
                tot.append(v)
                to_remove.append(k)

        for r in to_remove:
            del self.definition_statements[r]

        for k, v in self.names_to_calculating_expression.items():
            if k in stat:
                tot.append(v)
        return tot

    def handle_inst_next_statement(self, stat: str):
        if "=" in stat:
            name, exp = stat.split("=", 1)
            name = name.strip()
            matching_replacers = [
                exp_repr for exp_repr in self.replacements if exp_repr.applies_to_expression(exp)]

            if len(matching_replacers) > 1:
                raise RuntimeError(
                    f"Conflicting replacers for expression: {exp}")
            if len(matching_replacers) == 1:
                self.prepare_statement(matching_replacers[0], name, exp)


def build_constructor(env: Environment, constructor: Match[str]) -> Optional[str]:
    semantics_section = constructor.group("semantics")

    statements = semantics_section.split(";")
    invis_ops = env.get_required_invisible_operands(statements)

    invisible_operand_list = "; "+"; ".join(invis_ops)
    if len(invis_ops) <= 0:
        invisible_operand_list = ""
    # check if we have an action section if we dont add one/ otherwise
    # action section ends at "]"
    has_action_section = constructor.group("action_section") is not None
    new_act_section = constructor.group(
        "action_section") if has_action_section else ""

    cons_start = constructor.start()
    cons_end = constructor.end()
    replaced_start = constructor.start(
        "action_section") if has_action_section else constructor.start("complete_semantics_section")
    replaced_end = constructor.end("complete_semantics_section")
    new_section = []
    used_priors = False
    for stat in semantics_section.split(";"):
        for prior in env.get_priors(stat):
            new_section.append(prior)
            used_priors = True
        new_section.append(stat)

    if not used_priors:
        return None

    str_sec = ";\n".join(new_section)

    # print(replaced_cons)
    return f"{constructor.string[cons_start:replaced_start]} {invisible_operand_list} {new_act_section} {{ \n{str_sec}  }}\n {constructor.string[replaced_end:cons_end]}"


ENDIAN_DEF_REGEX = "define\s*endian\s*=[\w()$]+;"


class MacroInfo:
    OPENS = set(["@if", "@ifdef"])
    CLOSES = set(["@endif"])

    TOKEN_REGEX = r"@if|@ifdef|@endif"

    def __init__(self, text) -> None:
        self.closed_locs = SortedSet()
        self.open_locs = SortedSet()
        tokens = re.compile(MacroInfo.TOKEN_REGEX)

        state = 0
        for item in tokens.finditer(text):
            content = item.string[item.start():item.end()]
            next_state = state
            if content in MacroInfo.OPENS:
                next_state += 1
            elif content in MacroInfo.CLOSES:
                next_state -= 1

            if state > 0 and next_state <= 0:
                self.closed_locs.add(item.end())

            if state <= 0 and next_state > 0:
                self.open_locs.add(item.start())
            state = next_state

    def get_next_closed_location(self, curr_loc: int) -> int:
        return self.closed_locs[self.closed_locs.bisect_left(curr_loc)]

    def is_in_macro(self, curr_loc: int) -> bool:
        if len(self.open_locs) == 0:
            return False

        macro_start = self.open_locs[max(
            self.open_locs.bisect_left(curr_loc) - 1, 0)]
        macro_end = self.closed_locs[self.closed_locs.bisect_left(
            macro_start)]
        return curr_loc >= macro_start and curr_loc < macro_end

    def complete_macro(self, curr_loc: int) -> int:
        return self.get_next_closed_location(curr_loc) if self.is_in_macro(curr_loc) else curr_loc

    def get_prev_closed_location(self, curr_loc: int) -> int:
        ind = self.open_locs.bisect_left(curr_loc)
        return self.open_locs[max(ind-1, 0)]

    def find_prev_closed(self, curr_loc: int) -> int:
        return self.get_prev_closed_location(
            curr_loc) if self.is_in_macro(curr_loc) else curr_loc


def generate_patch(target_file, pc_def_path, inst_next_size_hint, base_path, out_dir):
    print(CONSTRUCTOR_BASE_REGEX)
    print(CONTEXTREG_STATEMENT)
    construct_pat = re.compile(CONSTRUCTOR_BASE_REGEX)
    context_reg_def_pat = re.compile(CONTEXTREG_STATEMENT)

    commit_message = f"{Path(target_file).stem}"

    total_output = ""
    with open(target_file, 'r') as target_f:
        with open(pc_def_path) as pc_def_file:
            pc_def = pc_def_file.read()

            target = target_f.read()
            minfo = MacroInfo(target)

            # we know that an endian def has to be the first thing that occurs so go ahead and find that and sub in the preliminaries
            endian_def = re.search(ENDIAN_DEF_REGEX, target)

            target_insert_loc = 0
            if endian_def is not None:
                edef_end = minfo.complete_macro(endian_def.end())

                total_output += target[0:edef_end]

                # can insert our defs here
                # we only want to define this once in the file that also defines the endian-ness
                total_output += "\n" + pc_def
                total_output += "\ndefine pcodeop claim_eq;\n"

                target_insert_loc = next(
                    construct_pat.finditer(target)).start()
                # try to override the insert loc if possible to after context regs
                if context_reg_def_pat.match(target):
                    *_, last_match = context_reg_def_pat.finditer(target)
                    last_context_reg_def = last_match.end()
                    print("Last context reg def at: " +
                          str(last_context_reg_def))
                    target_insert_loc = last_context_reg_def
                    target_insert_loc = minfo.complete_macro(target_insert_loc)
                target_insert_loc = minfo.find_prev_closed(target_insert_loc)

                total_output += target[edef_end: target_insert_loc]

                if endian_def is not None:
                    # This should be defined once and it MUST be defined after all context definitions
                    total_output += f"\n{REMILL_INSN_SIZE_NAME}: calculated_size is epsilon [calculated_size= inst_next-inst_start; ] {{ local insn_size_hinted:{inst_next_size_hint}=calculated_size; \n export insn_size_hinted; }}\n"

            last_offset = target_insert_loc
            cont = Context()
            for constructor in construct_pat.finditer(target):
                total_output += constructor.string[last_offset:constructor.start()]
                last_offset = constructor.end()
                env = Environment(cont,
                                  inst_next_size_hint, [InstStartReplacer(), InstNextReplacer()])
                act_section = constructor.group("action_section")
                if act_section:
                    statements = act_section[
                        1: -1].split(";")
                    for stat in statements:
                        env.handle_inst_next_statement(stat)
                if len(env.names_to_calculating_expression) > 0:
                    maybe_new_cons = build_constructor(env, constructor)
                    if maybe_new_cons:
                        total_output += maybe_new_cons
                    else:
                        total_output += constructor.string[constructor.start(
                        ): constructor.end()]

            total_output += target[last_offset:]

            # compute the patch header
            src_and_dst = os.path.relpath(target_file, base_path)

            # compute the patch

    with open(target_file, 'w') as target_f:
        target_f.write(total_output)

    res = subprocess.run(["git", "commit", "-a", "-m", commit_message],
                         cwd=base_path, capture_output=True)

    print(res)
    print(subprocess.run(
        ["git", "format-patch", "-1", "HEAD", "-o", out_dir], cwd=base_path, capture_output=True))

    subprocess.run(
        ["git", "reset", "--hard", "HEAD~1"], cwd=base_path, capture_output=True)


def main():
    prsr = argparse.ArgumentParser("Disassembly action replacer")
    prsr.add_argument("target_files", nargs="+", help="List of files to patch")
    prsr.add_argument("--pc_def", required=True,
                      help="Path to file containing definition of INST_NEXT_PTR")
    prsr.add_argument("--inst_next_size_hint", required=True,
                      help="Number of bytes of the PC register")
    prsr.add_argument("--base_path", required=True,
                      help="Path to Ghidra git repo")
    prsr.add_argument("--out_dir", required=True)

    args = prsr.parse_args()

    for target in args.target_files:
        print(f"Processing {target}")
        generate_patch(target, args.pc_def,
                       args.inst_next_size_hint, args.base_path, args.out_dir)


if __name__ == "__main__":
    main()
