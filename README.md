# Fnord

Fnord is a pattern extractor for obfuscated code.

# Description

Fnord has two main functions:

1. Extract byte sequences and create some statistics
2. Use these statistics, combine length, number of occurrences, similarity and keywords to create a YARA rule

# 1. Statistics

Fnord processes the file with a sliding window of varying size to extract all sequences of with a minimum length `-m X` (default: 4) up to a maximum length `-x X` (default: 40). For each length, Fnord will present the most frequently occurring sequences `-t X` (default: 3) in a table.

Each line in the table contains:

- Length
- Number of occurrences
- Sequence (string)
- Formatted (ascii/wide/hex)
- Hex encoded form
- Entropy

# 2. YARA Rule Creation

By using the `--yara` flag, Fnord generates an experimental YARA rule. During YARA rule creation it will calculate a score based in the length of the sequence and the number of occurrences (length * occurrences). It will then process each sequences by removing all non-letter characters and comparing them with a list of keywords (case-insensitive) to detect sequences that are more interesting than others. Before writing each string to the rule Fnord calculates a Levenshtein distance and skips sequences that are too similar to sequences that have already been integrated in the rule.

# Usage

```
        ____                 __
       / __/__  ___  _______/ /
      / _// _ \/ _ \/ __/ _  /
     /_/ /_//_/\___/_/  \_,_/ Pattern Extractor
     v0.3, Florian Roth
    usage: fnord.py [-h] [-f file] [-m min] [-x max] [-t top] [-n min-occ]
                    [-e min-entropy] [--strings] [--yara] [--yara-strings max]
                    [--show-score] [--show-count] [--include-padding] [--debug]

    Grimoire

    optional arguments:
      -h, --help          show this help message and exit
      -f file             File to process
      -m min              Minimum sequence length
      -x max              Maximum sequence length
      -t top              Number of items in the Top x list
      -n min-occ          Minimum number of occurrences to show
      -e min-entropy      Minimum entropy
      --strings           Show strings only
      --yara              Generate an experimental YARA rule
      --yara-strings max  Maximum sequence length
      --show-score        Show score in comments of YARA rules
      --show-count        Show count in sample in comments of YARA rules
      --include-padding   Include 0x00 and 0x20 in the extracted strings
      --debug             Debug output
```

# Getting Started

1. `git clone https://github.com/Neo23x0/Fnord.git` and `cd Fnord`
2. `pip3 install -r ./requirements.txt`
3. `python3 ./fnord.py --help`

# Examples

```
python3 fnord.py -f ./test/wraeop.sct --yara --yara-strings 10
```

```
python3 fnord.py -f ./test/inv-obf.txt --yara --show-score --show-count -t 1
```

```
python3 fnord.py -f ./test/bash-obfusc.txt --yara --show-score --show-count --yara-strings 10 -t 2
```

```
python3 fnord.py -f ./test/launch-varplus.txt --yara --show-score --show-count --yara-strings 10 -t 2
```

# Screenshots

![Fnord Screenshot](https://github.com/Neo23x0/Fnord/blob/master/screens/fnord1.png "Fnord in action")

![Fnord Screenshot](https://github.com/Neo23x0/Fnord/blob/master/screens/fnord2.png "Fnord in action")