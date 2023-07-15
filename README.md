# Obfuscation Detection (v1.8)
Author: **Tim Blazytko**

_Automatically detect obfuscated code and other interesting code constructs_

## Description:

_Obfuscation Detection_ is a Binary Ninja plugin to detect obfuscated code and interesting code constructs (e.g., state machines) in binaries. Given a binary, the plugin eases analysis by identifying code locations which might be worth a closer look during reverse engineering.

Based on various heuristics, the plugin pinpoints functions that contain complex or uncommon code constructs. Such code constructs may implement

* obfuscated code
* state machines and protocols
* C&C server communication
* string decryption routines
* cryptographic algorithms

The following blog posts provide more information about the underlying heuristics and demonstrate their use cases:

* [Automated Detection of Control-flow Flattening](https://synthesis.to/2021/03/03/flattening_detection.html)
* [Automated Detection of Obfuscated Code](https://synthesis.to/2021/08/10/obfuscation_detection.html)
* [Statistical Analysis to Detect Uncommon Code](https://synthesis.to//2023/01/26/uncommon_instruction_sequences.html)

Some example use cases can be found in [examples](./examples). Furthermore, the REcon talk ["Unveiling Secrets in Binaries using Code Detection Strategies"](https://cfp.recon.cx/2023/talk/QD8UNJ/) demonstrates some use cases. The slides can be found [here](./presentation/recon23_code_detection.pdf); the recording can be found [here](https://www.youtube.com/watch?v=y95MNr2Xu-g).


## Core Features

* identifies interesting code constructs in large binaries
* highlights disaligned instructions in Binary Ninja's graph view
* efficient and architecture-agnostic implementation
* runs as a background task
* can be used in UI and headless mode


## Installation

The tool can be installed using Binary Ninja's plugin manager.

For the headless version, follow these steps:

```
git clone https://github.com/mrphrazer/obfuscation_detection.git
cd obfuscation_detection

# install obfuscation_detection
pip install .
```


## Usage

The plugin can be used in the user interface and in headless mode.

### User Interface

Choose the index tab `Plugins -> Obfuscation Detection` to run one or more detection heuristics in Binary Ninja's user interface:

<p align="left">
<img alt="Plugin Menu" src="imgs/plugin_menu.png" width="500"/>
</p>

The results are displayed in the Log window:

<p align="center">
<img alt="Binary Ninja Log" src="imgs/plugin_results.png"/>
</p>

By clicking on the identified function addresses, Binary Ninja navigates to the selected function.


### Headless

To use the plugin in headless mode, run [`scripts/detect_obfuscation.py`](scripts/detect_obfuscation.py):

```
$ python3 scripts/detect_obfuscation.py <binary>
```


## Detection Heuristics

The plugin implements various detection heuristics to detect different code constructs. In the following, we briefly describe the individual heuristics and explain their usage. 

### Large Basic Blocks

The large basic block heuristic identifies the top 10% of functions with the largest average number of instructions per basic block. It allows to detect

* unrolled code
* cryptographic implementations
* initialization routines
* arithmetic obfuscation / Mixed Boolean-Arithmetic

### Complex Functions

To complex functions heuristic identifies the top 10% of functions with the most complex control-flow graphs (based on cyclomatic complexity). It allows to identify

* complex dispatching routines and protocols
* state machines
* functions obfuscated with opaque predicates


### Flattened Functions

The flattened function heuristic uses some graph-theoretic properties to identify functions implementing state machines. Usually, such state machines can be represented as switch statements that are dispatched in a loop. The heuristic allows to identify

* network protocol dispatching
* file parsing logic
* C&C server communication / command dispatching
* control-flow flattening


### Uncommon Instruction Sequences

The uncommon instruction sequences heuristic performs a statistical analysis to identify the top 10% of functions whose code patterns deviate from a pre-computed ground truth. This way, the heuristic allows to identify

* cryptographic implementations
* intense usage of floating point arithmetic
* arithmetic obfuscation / Mixed Boolean-Arithmetic
* generic obfuscation patterns


### Instruction Overlapping

The instruction overlapping heuristic identifies functions with disaligned instructions (instruction bytes are shared by two different instructions). The heuristic identifies

* broken disassembly (e.g., data which is marked as code)
* opaque predicates which jump into other instructions 

If the heuristic is used in Binary Ninja's user interface, overlapping instructions are also highlighted in the graph view.


### Most Called Functions

The heuristic for most called functions identifies the top 10% of functions with the largest number of calls from different functions. This way, the heuristic can identify

* string decryption routines
* library functions in statically linked binaries


### XOR Decryption Loops

The heuristic identifies functions which perform an XOR operation with a constant inside of a loop. This way, the heuristic can identify

* string decryption routines
* code decryption stubs
* cryptographic implementations


## Contact

For more information, contact [@mr_phrazer](https://twitter.com/mr_phrazer).

