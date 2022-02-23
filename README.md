# Obfuscation Detection (v1.4)
Author: **Tim Blazytko**

_Automatically detect obfuscated code and other state machines_

## Description:

Scripts and binaries to automatically detect obfuscated code and state machines in binaries.

Implementation is based on Binary Ninja. Check out the following blog posts for more information:

* [Automated Detection of Control-flow Flattening](https://synthesis.to/2021/03/03/flattening_detection.html)
* [Automated Detection of Obfuscated Code](https://synthesis.to/2021/08/10/obfuscation_detection.html)

## Usage

To detect control-flow flattening, run `detect_flattening.py`:

```
$ ./detect_flattening.py samples/finspy 
Function 0x401602 has a flattening score of 0.9473684210526315.
Function 0x4017c0 has a flattening score of 0.9981378026070763.
Function 0x405150 has a flattening score of 0.9166666666666666.
Function 0x405270 has a flattening score of 0.9166666666666666.
Function 0x405370 has a flattening score of 0.9984544049459042.
Function 0x4097a0 has a flattening score of 0.9992378048780488.
Function 0x412c70 has a flattening score of 0.9629629629629629.
Function 0x412df0 has a flattening score of 0.9629629629629629.
Function 0x412f70 has a flattening score of 0.9927007299270073.
Function 0x4138e0 has a flattening score of 0.9629629629629629.
```

To apply various heuristics to detect obfuscated code, run `detect_obfuscation.py`:

```
$ ./detect_obfuscation.py samples/finspy 
================================================================================
Control Flow Flattening
Function 0x401602 (sub_401602) has a flattening score of 0.9473684210526315.
Function 0x4017c0 (sub_4017c0) has a flattening score of 0.9981378026070763.
Function 0x405150 (sub_405150) has a flattening score of 0.9166666666666666.
Function 0x405270 (sub_405270) has a flattening score of 0.9166666666666666.
Function 0x405370 (sub_405370) has a flattening score of 0.9984544049459042.
Function 0x4097a0 (sub_4097a0) has a flattening score of 0.9992378048780488.
Function 0x412c70 (sub_412c70) has a flattening score of 0.9629629629629629.
Function 0x412df0 (sub_412df0) has a flattening score of 0.9629629629629629.
Function 0x412f70 (sub_412f70) has a flattening score of 0.9927007299270073.
Function 0x4138e0 (sub_4138e0) has a flattening score of 0.9629629629629629.
================================================================================
Cyclomatic Complexity
Function 0x4097a0 (sub_4097a0) has a cyclomatic complexity of 524.
Function 0x405370 (sub_405370) has a cyclomatic complexity of 258.
Function 0x4017c0 (sub_4017c0) has a cyclomatic complexity of 214.
Function 0x412f70 (sub_412f70) has a cyclomatic complexity of 54.
Function 0x4138e0 (sub_4138e0) has a cyclomatic complexity of 10.
Function 0x412df0 (sub_412df0) has a cyclomatic complexity of 10.
================================================================================
Large Basic Blocks
Basic blocks in function 0x405340 (sub_405340) contain on average 11 instructions.
Basic blocks in function 0x401240 (_start) contain on average 11 instructions.
Basic blocks in function 0x4013e3 (sub_4013e3) contain on average 10 instructions.
Basic blocks in function 0x413a80 (init) contain on average 9 instructions.
Basic blocks in function 0x401349 (sub_401349) contain on average 7 instructions.
Basic blocks in function 0x401030 (_init) contain on average 6 instructions.
================================================================================
Instruction Overlapping
```


## Note

The password for the zipped malware samples is "infected". To unpack, use the following command line:

```
$ unzip -P infected samples.zip
```

## Contact

For more information, contact [@mr_phrazer](https://twitter.com/mr_phrazer).

