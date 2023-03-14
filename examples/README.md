# Example Use Cases

The malware samples in `samples.zip` can be used to test the plugin and reproduce the results from the blog posts. To unpack, use the passwort "infected" or the following command:

```
$ unzip -P infected samples.zip
```

In particular, the following samples `emotet`, `adylkuzz` and `plugx` are worth a closer look.


## Emotet

`emotet` obfuscates its control-flow via control-flow flattening, which can be identified by the flattening heuristic. Furthermore, the heuristic for uncommon instruction sequences pinpoints functions which apply arithmetic encodings to the control-flow flattening states.


## Adylkuzz

`adylkuzz` is protected by VMProtect. It uses various anti-disassembly tricks like opaque predicates which jump into disaligned code, causing the disassembler to produce invalid disassembly and garbage code. Using the instruction overlapping heuristic, a majority of these functions with garbage code can be identified.


## PlugX

`plugx` is not obfuscated. However, the flattening heuristic can be used to identify the communication with the command and control server as well as command dispatching routines.
