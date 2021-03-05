# Obfuscation Detection (v1.0)
Author: **mr_phrazer**

_Automatically detect control-flow flattening and other state machines_

## Description:

Scripts and binaries to automatically detect control-flow flattening and other state machines in binaries.

Implementation is based on Binary Ninja. Check out the following blog post for more information:

[Automated Detection of Control-flow Flattening](https://synthesis.to/2021/03/03/flattening_detection.html)

## Usage

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

## Note

The password for the zipped malware samples is "infected". To unpack, use the following command line:

```
$ unzip -P infected samples.zip
```

## Contact

For more information, contact [@mr_phrazer](https://twitter.com/mr_phrazer).

