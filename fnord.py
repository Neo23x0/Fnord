#!/usr/bin/env python3
#
# Fnord
# Extracting code from scrambled code that could be used in signature based detection

__author__ = "Florian Roth"
__version__ = "0.6"

import sys
import argparse
import math
import datetime
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
rule gen_experimemtal_rule_%%%settings%%% {
   meta: 
      description = "%%%description%%%"
      date = "%%%date%%%"
      author = "%%%author%%%"
   strings: 
      %%%strings%%%
   condition:
      %%%magics%%%%%%condition%%%
}
"""

KEYWORDS = ['char', 'for', 'set', 'string', 'decode', 'encode', 'b64', 'base64', 'hex', 'compress', 'reverse', 'xor',
            'cmd', 'powershell', 'shell', 'script', 'print', 'temp', 'appdata', 'system32', 'each', 'certutil',
            'msiexec', 'hidden']

# Presets for the different YARA rule variants
# s = allowed similarity
# k = keyword score multiplier
# r = structure code multiplier (only non-letter characters)
# c = count limiter (limit the influence of a sequence occurrence on the score)
PRESETS = [{"s": 0.8, "k": 2, "r": 1, "c": 50},
           {"s": 1, "k": 1, "r": 1, "c": 20},
           {"s": 2, "k": 5, "r": 2, "c": 10},
           {"s": 1, "k": 1, "r": 5, "c": 5}]

RE_STRUCTURE = re.compile("^[%s\s0-9]+$" % re.escape(string.punctuation))


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
            # End of file data
            if (i+c) > len(blob):
                continue
            # Read a chunk
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

    tabulate.PRESERVE_WHITESPACE = True
    print(tabulate(seq_set_extended, ["Length", "Count", "Sequence", "Formatted", "Hex Sequence", "Entropy"],
                   tablefmt="fancy_grid"))


def calculate_score(b, c, settings):
    """
    Calculate a score for a byte / sequence combination
    :param b: byte sequence
    :param c: count
    :param settings:
    :return: score
    """
    # Based on count and length
    # limit the values
    if c > 100:
        c = 100
    # Wide length / 2
    div = 1
    if is_wide_formatted(b):
        div = 2
    # Now calculate the score
    score = ( len(b) / div ) * c
    # Does the sequence contain a certain keyword if you remove all non-letter characters from the sequence
    if contains_keyword(b):
        score = score * float(settings['k'])
    # Does the sequence consist of structure characters only (non-payload)
    if is_structure(b):
        score = score * float(settings['r'])
    return score


def is_structure(b):
    """
    Tries to evaluate the type of the the sequences - payload or structure - structure is more stable over various
    samples that have been obfuscated with the same method
    :param b:
    :return:
    """
    try:
        if RE_STRUCTURE.search(b.decode('utf-8')):
            # print(b.decode('utf-8'), " Structure!")
            return True
        return False
    except UnicodeDecodeError as e:
        pass
    return False


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


def contains_keyword_uncommon_casing(s):
    """
    Checks if a sequence contains a special keyword if all non-letters are removed in a suspicious casing
    :param b:
    :return:
    """
    ascii_letters = set(string.ascii_letters)
    try:
        s_filtered = "".join(filter(lambda x: x in ascii_letters, s))
        s_filtered_lower = s_filtered.lower()
        keywords_contained = list(filter(lambda x: x.lower() in s_filtered_lower, KEYWORDS))
        if len(keywords_contained) > 0:
            for k in keywords_contained:
                if k.lower() not in s_filtered and \
                        k.upper() not in s_filtered and \
                        k.title() not in s_filtered:
                    return True
            return False
    except UnicodeDecodeError as e:
        pass
    return False


def is_similar(value, strings, settings):
    """
    Checks is a string is similar to one in a set of strings
    :param value:
    :param strings:
    :param settings:
    :return:
    """
    levenshtein = Levenshtein()
    for s in strings:
        if levenshtein.distance(value, s) < (len(value)/settings["s"]):
            return True
    return False


def get_magic_condition(filename):
    """
    Generate a condition element that matches the exact header and footer of the file
    :param data: the full file data blob
    :return magic_condition: condition that can be used in YARA rules that matches magic header and footer of a file
    """
    magic_condition = ""
    try:
        with open(filename, 'rb') as fh:
            data = fh.read()
        head = binascii.hexlify(data[:4]).decode('utf-8')
        foot = binascii.hexlify(data[-4:]).decode('utf-8')
        magic_condition = "uint32be(0) == 0x%s and uint32be(filesize-4) == 0x%s and " % (head, foot)
    except Exception as e:
        traceback.print_exc()
    return magic_condition


def replace_illegal_escape_sequences(s):
    """
    Replace illegal escape sequences in YARA
    :param s:
    :return:
    """
    return s.replace(r'\r', r'\x0d')


def get_yara_rule(seq_set, magic_condition, settings,
                    yara_string_count, show_score=False, show_count=False, debug=False):
    """
    Generates an experimental YARA rule
    :param seq_set:
    :param yara_string_count:
    :param show_score:
    :param show_count:
    :return:
    """
    strings = []

    for b, c in seq_set.items():
        # Count limiter
        count = c
        if count > settings["c"]:
            count = settings["c"]
        # Calculate a score
        score = calculate_score(b, count, settings)
        # By default - use the hex value
        value = binascii.hexlify(b).decode("utf-8")
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
        print("[+] Sorting %d strings ... " % len(strings))
    strings_sorted = sorted(strings, key=lambda k: k['score'], reverse=True)

    # Generate the string values
    included_strings = []
    string_content = []
    condition_content = []
    c = 1
    for s in strings_sorted:
        # Too similar to the others
        if is_similar(s['value'], included_strings, settings):
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
        keywords = []
        if s["format"] != "hex":
            keywords.append(s['format'])  # ascii/wide
            if contains_keyword_uncommon_casing(s['value']):
                keywords.append("nocase")
        # Now compose the line
        string_content.append('$s%d = "%s" %s%s' %(c, replace_illegal_escape_sequences(s['value']),
                                                   " ".join(keywords), add_value))
        # Add the line to the list
        included_strings.append(s['value'])
        # Conditions
        occ = round(s["count"] / 2)
        if occ < 2:
            condition_content.append("$s%d" % c)
        else:
            condition_content.append("#s%d > %d" % (c, occ))
        c += 1
        # Enough
        if c > yara_string_count:
            break

    rule_value = RULE_TEMPLATE
    rule_value = rule_value.replace('%%%settings%%%', "".join(filter(lambda x: x in set(string.ascii_letters + string.digits), str(settings))))
    rule_value = rule_value.replace('%%%description%%%',
                                    "Fnord rule generated with settings %s" % settings)
    rule_value = rule_value.replace('%%%date%%%', str(datetime.datetime.now().strftime("%Y-%m-%d")))
    rule_value = rule_value.replace('%%%author%%%', args.author)
    rule_value = rule_value.replace('%%%strings%%%', "\n      ".join(string_content))
    rule_value = rule_value.replace('%%%magics%%%', magic_condition)
    rule_value = rule_value.replace('%%%condition%%%', " and ".join(condition_content))

    return rule_value

if __name__ == '__main__':

    print("    ____                 __ ".ljust(80))
    print("   / __/__  ___  _______/ / ".ljust(80))
    print("  / _// _ \/ _ \/ __/ _  /  ".ljust(80))
    print(" /_/ /_//_/\___/_/  \_,_/ Pattern Extractor for Obfuscated Code".ljust(80))
    print(" v{0}, {1}                  ".format(__version__, __author__).ljust(80))
    print(" ".ljust(80))

    parser = argparse.ArgumentParser(description='Fnord - Pattern Extractor for Obfuscated Code')
    parser.add_argument('-f', help='File to process', metavar='file', default='')
    parser.add_argument('-m', help='Minimum sequence length', metavar='min', default=5)
    parser.add_argument('-x', help='Maximum sequence length', metavar='max', default=15)
    parser.add_argument('-t', help='Number of items in the Top x list', metavar='top', default=3)
    parser.add_argument('-n', help='Minimum number of occurrences to show', metavar='min-occ', default=3)
    parser.add_argument('-e', help='Minimum entropy', metavar='min-entropy', default=1.5)
    parser.add_argument('--strings', action='store_true', default=False, help='Show strings only')
    parser.add_argument('--include-padding', action='store_true', default=False,
                        help='Include 0x00 and 0x20 in the extracted strings')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    group_yara = parser.add_argument_group('YARA Rule Creation')
    group_yara.add_argument('--noyara', action='store_true', default=False,
                            help='Do not generate an experimental YARA rule')

    # Rule Generation Settings
    default_similarity = float(1.5)
    default_keyword_multiplier = float(2)
    default_structure_multiplier = float(2)
    default_count_limiter = int(20)
    group_yara.add_argument('-s', help='Allowed similarity (use values between 0.1=low and 10=high, default=%0.1f)' %
                                       default_similarity,
                            metavar='similarity', default=default_similarity)
    group_yara.add_argument('-k', help='Keywords multiplier (multiplies score of sequences if keyword is found) '
                                       '(best use values between 1 and 5, default=%0.1f)' % default_keyword_multiplier,
                            metavar='keywords-multiplier',
                            default=default_keyword_multiplier)
    group_yara.add_argument('-r', help='Structure multiplier (multiplies score of sequences if it is identified as '
                                       'code structure and not payload) '
                                       '(best use values between 1 and 5, default=%0.1f)' % default_structure_multiplier,
                            metavar='structure-multiplier',
                            default=default_structure_multiplier)
    group_yara.add_argument('-c', help='Count limiter (limts the impact of the count by capping it at a certain amount) '
                                       '(best use values between 5 and 100, default=%d)' % default_count_limiter,
                            metavar='count-limiter',
                            default=default_count_limiter)

    group_yara.add_argument('--yara-exact', action='store_true', default=False,
                        help='Add magic header and magic footer limitations to the rule')
    group_yara.add_argument('--yara-strings', help='Maximum sequence length', metavar='max', default=4)
    group_yara.add_argument('--show-score', action='store_true', default=False,
                            help='Show score in comments of YARA rules')
    group_yara.add_argument('--show-count', action='store_true', default=False,
                        help='Show count in sample in comments of YARA rules')
    group_yara.add_argument('--author', help='YARA rule author', metavar='author',
                            default="Fnord %s" % __version__)
    group_yara.add_argument('-o', help='Output', metavar='yara-output', default="./fnord-rules.yar")

    # Obsolete
    group_yara.add_argument('--yara', action='store_true', default=False,
                            help=argparse.SUPPRESS)

    args = parser.parse_args()

    # Errors
    if args.yara:
        print("[E] The --yara flag has been deprecated in version 0.6 as it has become the default. Use --noyara if "
              "you want to disable the YARA rule output.")
        sys.exit(1)
    if not args.f:
        parser.print_help()
        sys.exit(0)

    # Read sequences
    seq_set = read_file(args.f, int(args.m), int(args.x), int(args.e),
                        include_padding=args.include_padding, strings_only=args.strings)
    # Print the most common sequences
    print_most_common(seq_set, int(args.t), int(args.m), int(args.x), int(args.n))

    # YARA
    if not args.noyara:

        # Magic condition (--yara-exact)
        magic_condition = ""
        if args.yara_exact:
            magic_condition = get_magic_condition(args.f)

        # Rules list
        rules = []
        rules_table = []

        # Configs for YARA rule generations
        settings = PRESETS

        # If user has set values other than the presets, use his settings
        if float(args.s) != default_similarity or \
                float(args.k) != default_keyword_multiplier or \
                float(args.r) != default_structure_multiplier or \
                int(args.c) != default_count_limiter:
                # user defined settings
                settings = [{"s": float(args.s), "k": float(args.k), "r": float(args.r), "c": int(args.c)}]

        # Loop through the configs
        print("Generating YARA rule with the following settings")
        print("Number of strings to include in the rule (--yara-strings): %d" % int(args.yara_strings))
        print("Add magic header anf footer expression (--yara-exact): %s" % str(args.yara_exact))
        print("Maximum considered sequence length (-x) [reduce to accelerate]: %d" % int(args.x))
        for c, config in enumerate(settings):
            print("Rule %d: Allowed similarity (-s): %0.1f Keyword multiplier (-k): %0.1f "
                  "Structure Multiplier (-r): %0.1f Count Limiter (-c): %d" %
                  (c+1, config["s"], config["k"], config["r"], config["c"]))

            rule_value = get_yara_rule(seq_set, magic_condition,
                                              yara_string_count=int(args.yara_strings),
                                              settings=config,
                                              show_score=args.show_score, show_count=args.show_count,
                                              debug=args.debug)
            rules.append(rule_value)
            rules_table.append([rule_value])

        print(tabulate(rules_table, ["YARA Rules"], tablefmt="rst"))

        with open(args.o, "w") as fh:
            fh.write("\n".join(rules))
