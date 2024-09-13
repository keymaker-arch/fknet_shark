#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Scan dissectors for calls to col_[set|add|append]_[f]str
# to check that most appropriate API is being used

import os
import re
import subprocess
import argparse
import signal


# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)


# Test for whether the given file was automatically generated.
def isGeneratedFile(filename):
    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        return False

    # Open file
    f_read = open(os.path.join(filename), 'r', encoding="utf8")
    lines_tested = 0
    for line in f_read:
        # The comment to say that its generated is near the top, so give up once
        # get a few lines down.
        if lines_tested > 10:
            f_read.close()
            return False
        if (line.find('Generated automatically') != -1 or
            line.find('Generated Automatically') != -1 or
            line.find('Autogenerated from') != -1 or
            line.find('is autogenerated') != -1 or
            line.find('automatically generated by Pidl') != -1 or
            line.find('Created by: The Qt Meta Object Compiler') != -1 or
            line.find('This file was generated') != -1 or
            line.find('This filter was automatically generated') != -1 or
            line.find('This file is auto generated, do not edit!') != -1 or
            line.find('This file is auto generated') != -1):

            f_read.close()
            return True
        lines_tested = lines_tested + 1

    # OK, looks like a hand-written file!
    f_read.close()
    return False


def removeComments(code_string):
    code_string = re.sub(re.compile(r"/\*.*?\*/",re.DOTALL ) ,"" ,code_string) # C-style comment
    code_string = re.sub(re.compile(r"//.*?\n" ) ,"" ,code_string)             # C++-style comment
    return code_string


def is_dissector_file(filename):
    p = re.compile(r'.*(packet|file)-.*\.c')
    return p.match(filename)

def findDissectorFilesInFolder(folder, recursive=False):
    dissector_files = []

    if recursive:
        for root, subfolders, files in os.walk(folder):
            for f in files:
                if should_exit:
                    return
                f = os.path.join(root, f)
                dissector_files.append(f)
    else:
        for f in sorted(os.listdir(folder)):
            if should_exit:
                return
            filename = os.path.join(folder, f)
            dissector_files.append(filename)

    return [x for x in filter(is_dissector_file, dissector_files)]



warnings_found = 0
errors_found = 0

class ColCall:
    def __init__(self, file, line_number, name, last_args, generated, verbose):
        self.filename = file
        self.line_number = line_number
        self.name = name
        self.last_args = last_args
        self.generated = generated
        self.verbose = verbose

    def issue_prefix(self):
        generated = '(GENERATED) ' if self.generated else ''
        return self.filename + ':' + generated + str(self.line_number) + ' : called ' + self.name + ' with ' + self.last_args

    def check(self):
        global warnings_found

        self.last_args = self.last_args.replace('\\\"', "'")
        self.last_args = self.last_args.strip()

        # Empty string never a good idea
        if self.last_args == r'""':
            if self.name.find('append') == -1:
                print('Warning:', self.issue_prefix(), '- if want to clear column, use col_clear() instead')
                warnings_found += 1
            else:
                # TODO: pointless if appending, but unlikely to see
                pass

        # This is never a good idea..
        if self.last_args.startswith(r'"%s"'):
            print('Warning:', self.issue_prefix(), " - don't need fstr API?")
            warnings_found += 1

        # Unlikely, but did someone accidentally include a specifier but call str() function with no args?
        if self.last_args.startswith('"') and self.last_args.find("%") != -1 and self.name.find('fstr') == -1:
            print('Warning:', self.issue_prefix(), " - meant to call fstr version of function?")
            warnings_found += 1

        ternary_re = re.compile(r'.*\s*\?\s*.*\".*\"\s*:\s*.*\".*\"')

        # String should be static, or at least persist.
        # TODO: how persistent does it need to be.  Which memory scope is appropriate?
        if self.name == 'col_set_str':
            # Literal strings are safe, as well as some other patterns..
            if self.last_args.startswith('"'):
                return
            elif self.last_args.startswith('val_to_str_const') or self.last_args.startswith('val_to_str_ext_const'):
                return
            # TODO: substitute macros to avoid some special cases..
            elif self.last_args.upper() == self.last_args:
                return
            # Ternary test with both outcomes being literal strings?
            elif ternary_re.match(self.last_args):
                return
            else:
                if self.verbose:
                    # Not easy/possible to judge lifetime of string..
                    print('Note:', self.issue_prefix(), '- is this persistent enough??')

        if self.name == 'col_add_str':
            # If literal string, could have used col_set_str instead?
            self.last_args = self.last_args.replace('\\\"', "'")
            self.last_args = self.last_args.strip()
            if self.last_args.startswith('"'):
                print('Warning:', self.issue_prefix(), '- could call col_set_str() instead')
                warnings_found += 1
            elif self.last_args.startswith('val_to_str_const'):
                print('Warning:', self.issue_prefix(), '- const so could use col_set_str() instead')
                warnings_found += 1
            elif self.last_args.startswith('val_to_str_ext_const'):
                print('Warning:', self.issue_prefix(), '- const so could use col_set_str() instead')
                warnings_found += 1

        if self.name == 'col_append_str':
            pass
        if self.name == 'col_add_fstr' or self.name == 'col_append_fstr':
            # Look at format string
            self.last_args = self.last_args.replace('\\\"', "'")
            m = re.search(r'"(.*?)"', self.last_args)
            if m:
                # Should contain at least one format specifier!
                format_string = m.group(1)
                if format_string.find('%') == -1:
                    print('Warning:', self.issue_prefix(), 'with no format specifiers  - "' + format_string + '" - use str() version instead')
                    warnings_found += 1


# Check the given dissector file.
def checkFile(filename, generated, verbose=False):
    global warnings_found
    global errors_found

    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        print(filename, 'does not exist!')
        return

    with open(filename, 'r', encoding="utf8") as f:
        full_contents = f.read()

        # Remove comments so as not to trip up RE.
        contents = removeComments(full_contents)

        # Look for all calls in this file
        matches = re.finditer(r'(col_set_str|col_add_str|col_add_fstr|col_append_str|col_append_fstr)\((.*?)\)\s*\;', contents, re.MULTILINE|re.DOTALL)
        col_calls = []

        last_line_number = 1
        last_char_offset = 0

        for m in matches:
            args = m.group(2)

            line_number = -1
            # May fail to find there were comments inside call...
            # Make search partial to:
            # - avoid finding an earlier identical call
            # - speed up searching by making it shorter
            remaining_lines_text =  full_contents[last_char_offset:]
            match_offset = remaining_lines_text.find(m.group(0))
            if match_offset != -1:
                match_in_lines = len(remaining_lines_text[0:match_offset].splitlines())
                line_number = last_line_number + match_in_lines-1
                last_line_number = line_number
                last_char_offset += match_offset + 1  # enough to not match again

            # Match first 2 args plus remainder
            args_m = re.match(r'(.*?),\s*(.*?),\s*(.*)', args)
            if args_m:
                col_calls.append(ColCall(filename, line_number, m.group(1), last_args=args_m.group(3),
                                         generated=generated, verbose=verbose))

        # Check them all
        for call in col_calls:
            call.check()



#################################################################
# Main logic.

# command-line args.  Controls which dissector files should be checked.
# If no args given, will scan all dissectors.
parser = argparse.ArgumentParser(description='Check calls in dissectors')
parser.add_argument('--file', action='append',
                    help='specify individual dissector file to test')
parser.add_argument('--commits', action='store',
                    help='last N commits to check')
parser.add_argument('--open', action='store_true',
                    help='check open files')
parser.add_argument('--verbose', action='store_true',
                    help='show extra info')


args = parser.parse_args()


# Get files from wherever command-line args indicate.
files = []
if args.file:
    # Add specified file(s)
    for f in args.file:
        if not os.path.isfile(f) and not f.startswith('epan'):
            f = os.path.join('epan', 'dissectors', f)
        if not os.path.isfile(f):
            print('Chosen file', f, 'does not exist.')
            exit(1)
        else:
            files.append(f)
elif args.commits:
    # Get files affected by specified number of commits.
    command = ['git', 'diff', '--name-only', 'HEAD~' + args.commits]
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Will examine dissector files only
    files = list(filter(lambda f : is_dissector_file(f), files))
elif args.open:
    # Unstaged changes.
    command = ['git', 'diff', '--name-only']
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files = list(filter(lambda f : is_dissector_file(f), files))
    # Staged changes.
    command = ['git', 'diff', '--staged', '--name-only']
    files_staged = [f.decode('utf-8')
                    for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files_staged = list(filter(lambda f : is_dissector_file(f), files_staged))
    for f in files_staged:
        if f not in files:
            files.append(f)
else:
    # Find all dissector files from folder.
    files =  findDissectorFilesInFolder(os.path.join('epan', 'dissectors'))
    files += findDissectorFilesInFolder(os.path.join('plugins', 'epan'), recursive=True)
    files += findDissectorFilesInFolder(os.path.join('epan', 'dissectors', 'asn1'), recursive=True)


# If scanning a subset of files, list them here.
print('Examining:')
if args.file or args.commits or args.open:
    if files:
        print(' '.join(files), '\n')
    else:
        print('No files to check.\n')
else:
    print('All dissectors\n')


# Now check the chosen files
for f in files:
    if should_exit:
        exit(1)

    checkFile(f, isGeneratedFile(f), verbose=args.verbose)


# Show summary.
print(warnings_found, 'warnings found')
if errors_found:
    print(errors_found, 'errors found')
    exit(1)
