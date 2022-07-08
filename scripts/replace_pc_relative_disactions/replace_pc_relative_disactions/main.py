import argparse
import re
from typing import Dict, List, Match, Optional, Set, Tuple
import os
import tempfile
import subprocess
import abc

CONNECTIVES_WITHOUT_SEMICOLON = "&|.!"
CONNECTIVES = CONNECTIVES_WITHOUT_SEMICOLON+r";"

OPERATORS = r"*\-+\>\<\(\)$"

PCODE_SPECIFIC_OPERATORS = r"\[\]:="

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
        return []


class Environment:
    def __init__(self, cont: Context, size_hint: str, replacements: List[ExpressionReplacer]) -> None:
        self.name_to_invisible_variables: Dict[str, Set[str]] = {}
        self.names_to_calculating_expression: Dict[str, str] = {}
        self.definition_statements: Dict[str, str] = {}
        self.cont = cont
        self.size_hint = size_hint
        self.replacements = replacements
        self.handle_inst_next_statement("inst_next=inst_next")
        self.handle_inst_next_statement("inst_start=inst_start")

    def prepare_statement(self, repl: ExpressionReplacer,  name: str, exp: str):
        replaced_exp = repl.generate_unfolded_exp(exp)
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


def main():
    prsr = argparse.ArgumentParser("Disassembly action replacer")
    prsr.add_argument("target_file")
    prsr.add_argument("--pc_def", required=True)
    prsr.add_argument("--inst_next_size_hint", required=True)
    prsr.add_argument("--base_path", required=True)
    prsr.add_argument("--out", required=True)

    args = prsr.parse_args()
    print(CONSTRUCTOR_BASE_REGEX)
    construct_pat = re.compile(CONSTRUCTOR_BASE_REGEX)

    with open(args.target_file, 'r') as target_f:
        with open(args.pc_def) as pc_def_file:
            pc_def = pc_def_file.read()
            with open(args.out, 'w') as output_f:
                target = target_f.read()
                total_output = ""

                # we know that an endian def has to be the first thing that occurs so go ahead and find that and sub in the preliminaries
                endian_def = re.search(ENDIAN_DEF_REGEX, target)
                total_output += target[0:endian_def.end()]

                # can insert our defs here
                total_output += "\n" + pc_def
                total_output += "\ndefine pcodeop claim_eq;\n"

                first_constructor_offset = next(
                    construct_pat.finditer(target)).start()

                target_insert_match = max(filter(lambda k: k.end() < first_constructor_offset,
                                                 re.finditer("@endif", target)), key=lambda elem: elem.end())

                target_insert_loc = target_insert_match.end(
                ) if target_insert_match else (first_constructor_offset-1)

                total_output += endian_def.string[endian_def.end(): target_insert_loc]

                total_output += f"\n{REMILL_INSN_SIZE_NAME}: calculated_size is epsilon [calculated_size= inst_next-inst_start; ] {{ local insn_size_hinted:{args.inst_next_size_hint}=calculated_size; \n export insn_size_hinted; }}\n"

                last_offset = target_insert_loc
                cont = Context()
                for constructor in construct_pat.finditer(target):
                    total_output += constructor.string[last_offset:constructor.start()]

                    last_offset = constructor.end()
                    env = Environment(cont,
                                      args.inst_next_size_hint, [InstStartReplacer(), InstNextReplacer()])
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
                src_and_dst = os.path.relpath(args.target_file, args.base_path)

                # compute the patch
                with tempfile.NamedTemporaryFile() as temp_out:
                    temp_out.write(total_output.encode("utf8"))
                    temp_out.seek(0)

                    res = subprocess.run(
                        ["diff", "-u", args.target_file, temp_out.name], capture_output=True)

                    new_lines = [f"--- {src_and_dst}\n", f"+++ {src_and_dst}\n"] + \
                        [l.decode("utf8") +
                         "\n" for l in res.stdout.splitlines()[2:]]
                    print(len(new_lines))
                    output_f.writelines(new_lines)


if __name__ == "__main__":
    main()
