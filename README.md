# jarvis-scan
sidegrade of [scanflow](https://github.com/memflow/scanflow) with focus on more scan types, low memory footprint, and speed.

## Scan types 
- unknown value
- exact
- value between
- value within error
- changed 
- unchanged
- lower than
- higher than
- increased
- increased by
- decreased
- decreased by
- etc

## Low memory footprint
Achieved by storing 2 byte offsets instead of 8 byte addresses as well as storing the least amount of memory for the lowest time possible. In practice memory usage rarely goes much higher than that of the target process.

## Speed
It go loco :P

## Example
```
# linux 
git clone https://github.com/KawaiiKraken/jarvis-scan/; cd jarvis-scan; cargo r -r -- kvm explorer.exe
# windows 
git clone https://github.com/KawaiiKraken/jarvis-scan/; cd jarvis-scan; cargo r -r -- explorer.exe
```
