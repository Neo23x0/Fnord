# Fnord

Fnord is a pattern extractor for obfuscated code.

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