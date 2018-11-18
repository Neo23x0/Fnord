#!/usr/bin/env python3
#
# Fnord
# Extracting code from scrambled code that could be used in signature based detection

__author__ = "Florian Roth"
__version__ = "0.3"

import argparse
import math
import binascii
import traceback
import string
import re
from similarity.levenshtein import Levenshtein
from collections import Counter
from tabulate import tabulate

# Presets
PADDING_BYTES = [0x00, 0x20, 0x0a, 0x0d]  # null byte, space, new line, carriage return
RULE_TEMPLATE = """
rule gen_experimemtal_rule {
   strings: 
      %%%strings%%%
   condition:
      %%%condition%%%
}
"""
KEYWORDS = ['char', 'for', 'set', 'string', 'decode', 'encode', 'b64', 'base64', 'hex', 'compress', 'reverse', 'xor',
            'cmd', 'exe', 'powershell', 'shell', 'script', 'print']

def read_file(filename, seq_min, seq_max, min_entropy, include_padding=False, strings_only=False):
    """
    Read a file and build a set of code sequences of a certain length and bigger
    :param file:
    :seq_min: minimum size of a sequence
    :seq_max: maximum size of a sequence
    :include_padding: include 0x00 and 0x20 prefixes and suffixes in the extracted sequences
    :strings_only: extract only strings
    :return:
    """
    seq_set = Counter()  # key = sequence, val = count
    with open(filename, 'rb') as fh:
        blob = fh.read()

    # Process data blob
    for i in range(0, len(blob)):
        # cutting chunks
        for c in range (seq_min, seq_max):
            if (i+c) > len(blob):
                continue
            chunk = blob[i:i+c]
            # Skip some chunks
            if exclude_chunk(chunk, min_entropy, include_padding, strings_only):
                continue
            # Add the chunk to list
            seq_set.update([chunk])
    return seq_set


def exclude_chunk(chunk, min_entropy, include_padding, strings_only):
    """
    Exclude certain unusable chunks
    :param chunk: bytes chunk
    :param min_entropy: minimum entropy of a string to consider
    :param strings_only: extract only printable sequences
    :return:
    """
    if strings_only and not is_printable(chunk):
        return True
    if ( chunk[1] in PADDING_BYTES or chunk[-1] in PADDING_BYTES ):
        return True
    if entropy(chunk) < min_entropy:
        return True
    return False


def entropy(string):
    """
    Calculates the Shannon entropy of a string
    :param string:
    :return:
    """
    # get probability of chars in string
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    # calculate the entropy
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


def is_printable(byte_seq):
    """
    Checks if a sequences of bytes is printable
    :param byte_seq:
    :return:
    """
    try:
        s = byte_seq.decode('utf-8')
    except UnicodeDecodeError as e:
        return False
    return True


def replace_control_characters(s, replace_null=False):
    """
    Replace all control characters
    :param s:
    :return:
    """
    if replace_null:
        return s.decode('utf-8').encode('unicode_escape').replace(b'\\x00', b'')
    return s.decode('utf-8').encode('unicode_escape')


def is_wide_formatted(b):
    """
    Check if a sequence is wide formatted string
    :param b:
    :return:
    """
    r = re.compile(b"^[\x00]?([^\x00][\x00])+[^\x00]?$")
    if r.search(b):
        return True
    return False


def print_most_common(seq_set, num, min_seq, max_seq, min_occ):
    """
    Prints the most common sequences in a sequences set
    :param seq_set: sequence set
    :num: number of top items
    :min_seq:
    :max_seq:
    :min_occ:
    :return:
    """
    seq_set_extended = []

    for length in range(min_seq, max_seq+1):
        len_counter = Counter()
        for b, c in seq_set.items():
            if len(b) != length:
                continue
            if c < min_occ:
                continue
            len_counter.update({b: c})

        # Skip if no entries in a length set
        if len(len_counter) < 1:
            continue

        # Contents of each line in the table
        for b, c in len_counter.most_common(num):
            s_hex = binascii.hexlify(b)
            s_value = "(non ascii)"
            s_formatted = "hex"
            if is_printable(b):
                replace_null = False
                if is_wide_formatted(b):
                    s_formatted = "wide"
                    replace_null = True
                else:
                    s_formatted = "ascii"
                s_value = replace_control_characters(b, replace_null=replace_null)
            e = entropy(b)
            seq_set_extended.append([length, c, s_value, s_formatted, s_hex, e])

    print(tabulate(seq_set_extended, ["Length", "Count", "Sequence", "Formatted", "Hex Sequence", "Entropy"],
                   tablefmt="fancy_grid"))


def calculate_score(b, c):
    """
    Calculate a score for a byte / sequence combination
    :param b: byte sequence
    :param c: count
    :return: score
    """
    score = len(b) * c
    if contains_keyword(b):
        score += 70
    return score


def contains_keyword(b):
    """
    Checks if a sequence contains a special keyword if all non-letters are removed
    :param b:
    :return:
    """
    ascii_letters = set(string.ascii_letters)
    try:
        s_filtered = "".join(filter(lambda x: x in ascii_letters, b.decode('utf-8'))).lower()
        keywords_contained = list(filter(lambda x: x.lower() in s_filtered, KEYWORDS))
        if len(keywords_contained) > 0:
            return True
    except UnicodeDecodeError as e:
        pass
    return False


def is_similar(value, strings):
    """
    Checks is a string is similar to one in a set of strings
    :param value:
    :param strings:
    :return:
    """
    levenshtein = Levenshtein()
    for s in strings:
        if levenshtein.distance(value, s) < (len(value)/2):
            return True
    return False


def print_yara_rule(seq_set, yara_string_count=5, show_score=False, show_count=False, debug=False):
    """
    Generates an experimental YARA rule
    :param seq_set:
    :param yara_string_count:
    :param show_score:
    :param show_count:
    :return:
    """
    strings = []

    if debug:
        print("[D] String preperations ...")
    for b, c in seq_set.items():
        # Calculate a score
        score = calculate_score(b, c)
        # By default - use the hex value
        value = binascii.hexlify(b)
        # Evaluate the formatting - if printable / if ascii/wide
        s_formatted = "hex"
        if is_printable(b):
            replace_null = False
            if is_wide_formatted(b):
                s_formatted = "wide"
                replace_null = True
            else:
                s_formatted = "ascii"
            value = replace_control_characters(b, replace_null=replace_null).decode('utf-8')

        # Add string
        strings.append({
            "value": value,
            "score": score,
            "format": s_formatted,
            "count": c,
        })

    # Sort the contents based on the score
    if debug:
        print("[D] First sort ...")
    strings_sorted = sorted(strings, key=lambda k: k['score'], reverse=True)

    # Generate the string values
    included_strings = []
    string_content = []
    condition_content = []
    c = 1
    for s in strings_sorted:
        # Too similar to the others
        if is_similar(s['value'], included_strings):
            continue
        # Additional info
        adds = []
        if show_score:
            adds.append("score: %d" % s['score'])
        if show_count:
            adds.append("count: %d" % s['count'])
        add_value = ""
        if len(adds) > 0:
            add_value = " /* %s */" % (" ".join(adds))
        # Strings
        if s["format"] == "hex":
            string_content.append('$s%d = { %s }%s' % (c, s['value'], add_value))
        else:
            string_content.append('$s%d = "%s" %s%s' %(c, s['value'], s['format'], add_value))
        included_strings.append(s['value'])
        # Conditions
        occ = round(s['count'] / 2)
        if occ < 2:
            condition_content.append("$s%d" % c)
        else:
            condition_content.append("#s%d > %d" % (c, occ))
        c += 1
        # Enough
        if c > yara_string_count:
            break

    rule_value = RULE_TEMPLATE.replace(
        '%%%strings%%%', "\n      ".join(string_content)).replace(
        '%%%condition%%%', " and ".join(condition_content))

    print(tabulate([[rule_value]], ["YARA Rule"], tablefmt="rst"))


if __name__ == '__main__':

    print("    ____                 __ ".ljust(80))
    print("   / __/__  ___  _______/ / ".ljust(80))
    print("  / _// _ \/ _ \/ __/ _  /  ".ljust(80))
    print(" /_/ /_//_/\___/_/  \_,_/ Pattern Extractor ".ljust(80))
    print(" v{0}, {1}                  ".format(__version__, __author__).ljust(80))

    parser = argparse.ArgumentParser(description='Grimoire')
    parser.add_argument('-f', help='File to process', metavar='file', default='')
    parser.add_argument('-m', help='Minimum sequence length', metavar='min', default=5)
    parser.add_argument('-x', help='Maximum sequence length', metavar='max', default=40)
    parser.add_argument('-t', help='Number of items in the Top x list', metavar='top', default=3)
    parser.add_argument('-n', help='Minimum number of occurrences to show', metavar='min-occ', default=3)
    parser.add_argument('-e', help='Minimum entropy', metavar='min-entropy', default=1.5)
    parser.add_argument('--strings', action='store_true', default=False, help='Show strings only')
    parser.add_argument('--yara', action='store_true', default=False, help='Generate an experimental YARA rule')
    parser.add_argument('--yara-strings', help='Maximum sequence length', metavar='max', default=3)
    parser.add_argument('--show-score', action='store_true', default=False, help='Show score in comments of YARA rules')
    parser.add_argument('--show-count', action='store_true', default=False,
                        help='Show count in sample in comments of YARA rules')
    parser.add_argument('--include-padding', action='store_true', default=False,
                        help='Include 0x00 and 0x20 in the extracted strings')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    # Read sequences
    seq_set = read_file(args.f, int(args.m), int(args.x), int(args.e),
                        include_padding=args.include_padding, strings_only=args.strings)
    # Print the most common sequences
    print_most_common(seq_set, int(args.t), int(args.m), int(args.x), int(args.n))

    # YARA
    if args.yara:
        print_yara_rule(seq_set, int(args.yara_strings), args.show_score, args.show_count, args.debug)
