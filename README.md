# Repak GUI for STALKER 2

A simple GUI wrapper for [repak](https://github.com/trumank/repak) - an Unreal Engine .pak file tool, specifically designed for STALKER 2 modding.

## Features

- User-friendly graphical interface for unpacking and packing .pak files
- Batch unpacking of multiple .pak files
- Designed for STALKER 2 mod creation and management
- Fixed output directories for organized file management

## Requirements

- Python 3.x
- tkinter (usually included with Python)
- repak binary (included in this repository)

## Usage

Run the GUI:
```bash
python3 repak_gui.py
```

Or use the included shell script:
```bash
./run.sh
```

The application provides:
- **Unpack**: Extract .pak files to the `unpackedfiles` directory
- **Pack**: Create .pak files from a directory to the `packedfiles` directory
- **Batch Unpack**: Process multiple .pak files at once

## Credits

This GUI wrapper is built on top of **[repak](https://github.com/trumank/repak)** by trumank.

repak is a powerful command-line tool for working with Unreal Engine .pak files. All pak/unpak functionality is provided by repak - this project simply provides a graphical interface for convenience.

## License

This GUI wrapper is provided as-is for the STALKER 2 modding community. Please refer to the [original repak repository](https://github.com/trumank/repak) for its license terms.
