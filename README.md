# bakarm - Script to disassemble bytes as ARM / ARM64, based on Capstone
https://github.com/RamseyK/bakarm

Disassembles a stream of bytes from a file as ARM / ARM64 instructions using [Capstone](http://www.capstone-engine.org/).  Supports basic label resolution.  I wrote this because I got tired of taking a sledgehammer (IDA / Hopper) to arbitrary bytes when I just wanted to know if it was valid ARM code.  Inspired by Jonathan Levin's [disarm](http://newosxbook.com/tools/disarm.html).

## Usage:

```bash
usage: bakarm.py [-h] [-a ARCH] [-b BASE] [-o OFFSET] file

Disassemble a stream of bytes in a file as ARM/ARM64 instructions

positional arguments:
  file

optional arguments:
  -h, --help            show this help message and exit
  -a ARCH, --arch ARCH  Architecture to disassemble as: [arm, arm64]
  -b BASE, --base BASE  Virtual base address to use
  -o OFFSET, --offset OFFSET  Offset in the file to start at

```

I copy bakarm.py to /usr/local/bin/ for quick access and to grep output.


## Requirements:

* Python 3.5+
* Capstone

## License:
BSD
