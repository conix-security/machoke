#!/usr/bin/env python3
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Lancelot Bogard
#
# This file is part of Machoke.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License

import json
import argparse
import os
import sys
import tempfile

try:
    import r2pipe
    import mmh3
except ImportError as e:
    if "r2pipe" in str(e):
        exit("Error: Unable to load r2pipe module.\n\
        Please install this module using: 'pip install r2pipe'")
    else:
        exit("Error: Unable to load mmh3 module.\n\
        Please install this module using: 'pip install mmh3'")

class Machoke:
    """ Machoke master class """
    def __init__(self, binary, timeout, debug=False):
        self.mmh3_line = ""
        self.machoke_line = ""
        self.error = False
        err = tempfile.NamedTemporaryFile(delete=debug)
        sys.stderr.flush()
        os.dup2(err.fileno(), sys.stderr.fileno())
        # Open binary
        self.rdeux = r2pipe.open(binary)
        if not self.is_valid_file():
            self.kill("Not a valid binary file")
            return
        # Set timeout
        self.rdeux.cmd('e anal.timeout = {}'.format(timeout))
        # Analyse all
        self.rdeux.cmd('aaa')
        #print >> sys.stderrs
        try:
            last_line = open(err.name).read().strip().split("\n")[-2]
        except:
            last_line = ""
        if last_line == "Timeout!":
            self.kill("r2 timeout")
            return

        self.process_machoke()

    def process_machoke(self):
        # For each function in binary
        functions = self.get_all_functions()
        if functions is None:
            self.kill("r2 could not retrieve functions list")
            return

        for function in functions:
            machoke = self.get_machoke_from_function(function)
            self.machoke_line = "{}{}".format(self.machoke_line, machoke)
            self.mmh3_line = "{}{}".format(self.mmh3_line,
                hex(mmh3.hash(machoke) & 0xFFFFFFFF).replace("0x", "").replace("L", ""))
        self.rdeux.quit()

    def kill(self, message):
        """ Kill machoke """
        self.mmh3_line = message
        self.machoke_line = message
        self.rdeux.quit()
        self.error = True

    def is_valid_file(self):
        """ Check if file contains instructions """
        result = self.rdeux.cmd("iIj")
        res = json.loads(result.replace("\\", ""))
        return bool(res['havecode'])

    def get_machoke_from_function(self, function):
        """ Return machoke from specific """
        self.go_to_offset(function["offset"])
        agj_error = 0
        while True:
            try:
                fcode = self.get_current_function_code()
                break
            except:
                print >> sys.stderr, "Fail agj: %s"%hex(function["offset"])
            if agj_error == 5:
                break
            agj_error += 1
        blocks = []
        id_block = 1
        try:
            for block in fcode[0]["blocks"]:
                blocks.append(
                    {'id_block': id_block, 'offset': hex(block["offset"])}
                )
                id_block += 1
        except:
            # print("[ERROR] agj return empty.")
            return ""
        line = ""
        id_block = 1
        for block in fcode[0]["blocks"]:
            word = "{}:".format(id_block)
            for instruction in block["ops"]:
                # Check if call
                if instruction["type"] == "call":
                    word = "{}c,".format(word)
                    for ublock in blocks:
                        if hex(instruction["offset"] + 2) == ublock["offset"]:
                            word = "{}{},".format(word, ublock["id_block"])

                # Check if jmp
                if instruction["type"] == "jmp":
                    for ublock in blocks:
                        if instruction["esil"] == ublock["offset"]:
                            word = "{}{},".format(word, ublock["id_block"])

                # Check if conditional jmp
                elif instruction["type"] == "cjmp":
                    for ublock in blocks:
                        if hex(instruction["jump"]) == ublock["offset"]:
                            word = "{}{},".format(word, ublock["id_block"])
                        if hex(instruction["offset"] + 2) == ublock["offset"]:
                            word = "{}{},".format(word, ublock["id_block"])
                else:
                    pass
                if word[-2] == 'c':
                    for ublock in blocks:
                        if hex(instruction["offset"] + 4) == ublock["offset"]:
                            word = "{}{},".format(word, ublock["id_block"])

                    if word[-2] == 'c':
                        word = "{}{},".format(word, id_block + 1)

            if word[-1] == ":" and id_block != len(fcode[0]["blocks"]):
                word = "{}{},".format(word, id_block + 1)
            # Clean word
            if word[-1] == ",":
                word = "{};".format(word[:-1])
            elif word[-1] == ":":
                word = "{};".format(word)
            line = "{}{}".format(line, word)
            id_block += 1
        return line

    def get_current_function_code(self):
        """ Return instructions from current function """
        return json.loads(self.rdeux.cmd("agj"))

    def go_to_offset(self, offset):
        """ Move cursor to a specific offset """
        # Go to specific offset
        self.rdeux.cmd("s {}".format(offset))

    def get_all_functions(self):
        """ Return all functions """
        try:
            jsn = json.loads(self.rdeux.cmd("aflj"))
        except ValueError:
            return None
        return jsn

def null_stderr():
    sys.stderr.flush()
    err = open('/dev/null', 'a')
    os.dup2(err.fileno(), sys.stderr.fileno())

def main(args):
    '''
        main function for Machoke processing from cli
    '''
    if not args.verbose:
        null_stderr()
    files = []
    for file in args.file:
        if os.path.isfile(file):
            files.append(file)
        elif os.path.isdir(file):
            print("%s: Is a folder"%file)
        else:
            print("%s is not a file"%file)

    if args.recursive != None and os.path.isdir(args.recursive):
        for root, directories, filenames in os.walk(args.recursive):
            for filename in filenames:
                files.append(os.path.join(root, filename))
    total_files = len(files)
    i = 0
    # For each files
    for file in files:
        if args.write and check_if_machoke_exist(file, args.write):
            continue
        machoke = Machoke(file, args.timeout, args.debug)
        if args.csv:
            output = "{},{}".format(machoke.mmh3_line, file)
        else:
            output = "{}\t{}".format(machoke.mmh3_line, file)
        if not machoke.error:
            write_output(output, args.write)
        elif args.verbose:
            write_output(output, args.write)
        if args.verbose:
            i += 1
            print("[%0.2f%%] %s/%s -> %s"%((float(i*100)/total_files), i, total_files, file))

def write_output(data, output_file=None):
    if output_file:
        open(output_file, 'a+').write("%s\n"%data)
    else:
        print(data)

def check_if_machoke_exist(file, output_file):
    if os.path.isfile(output_file):
        for line in open(output_file).read().strip().split("\n"):
            if line[-len(file):] == file:
                return True
    return False

if __name__ == "__main__":
    __parser__ = argparse.ArgumentParser()
    __parser__.add_argument("file",
                            help="File to process Machoke of",
                            nargs='*')
    __parser__.add_argument("--verbose",
                            "-v",
                            help="Verbose mode. The name of each file is printed to standard error as it is being hashed",
                            action='store_true')
    __parser__.add_argument("--csv",
                            "-c",
                            help="Output as CSV format",
                            action='store_true')
    __parser__.add_argument("--recursive",
                            "-r",
                            help="Recursive mode")
    __parser__.add_argument("--timeout",
                            "-t",
                            help="Stop analyzing a sample after a couple of seconds",
                            type=int,
                            default=60)
    __parser__.add_argument("--write",
                            "-w",
                            help="Append output in specific file if not exist",
                            type=str)
    __parser__.add_argument("--debug",
                            "-d",
                            help="Set script in debug mode",
                            action='store_true')

    # Hello World
    if len(sys.argv) == 1:
        __parser__.print_help()
        exit(1)
    __args__ = __parser__.parse_args()
    main(__args__)
