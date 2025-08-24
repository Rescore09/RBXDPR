# Roblox Memory Dumper (RBXDPR)

**Version:** 0.1.0 \[BETA]
**Author:** Rescore99

---

## Description

RBXDPR is a memory scanning and pattern-dumping utility for Roblox, designed **for educational purposes only**.
It scans the Roblox process, finds specific byte patterns in memory, and outputs offsets to a text file.

> ⚠️ **Warning:** Use responsibly. This tool is intended for learning and research only. The author is not responsible for misuse.

---

## Features

* Scan Roblox process memory for patterns.
* Save found offsets to `offsets.txt`.
* Compatible with Windows 10+.
* Lightweight, pure Python solution using `ctypes` for memory access.
* User-friendly console output with color-coded logs (`colorama`).

---

## Requirements

* Python 3.8+
* Windows OS
* Packages:

```bash
pip install -r requirements.txt
```

---

## Installation

1. Clone the repository or download the source code.
2. Run `setup.bat` to install dependencies:

```bat
setup.bat
```

3. Run the program:

```bat
start.bat
```

---

## Usage

1. Make sure Roblox is running (`RobloxPlayerBeta.exe`).
2. Launch `start.bat` or run the script manually:

```bash
python main.py
```

3. Follow the console messages.
4. If patterns are found, offsets will be saved to `offsets.txt`.

---

## Patterns

The tool comes preloaded with educational patterns such as:

* `luaD_throw`
* `Print`
* `KTable`
* `Luau_Execute`
* `FireTouchIntrest`
* `EnableLoadModule`
* `FireMouseClick`

> You can add or modify patterns directly in the `patterns` list inside `patterns.json`.

---

## Disclaimer

> This project is intended **for educational purposes only**. Do not use it to exploit, hack, or cheat in Roblox or any other software.

---

## License

> MIT License © Rescore99


