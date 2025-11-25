## Symbol Download Script for KPH Dynamic Data

Downloads PE files and their corresponding PDB symbol files from Microsoft Symbol Server
based on entries in kphdyn.xml.

Usage:
    python download_symbols.py -xml=path/to/kphdyn.xml -symboldir=C:/Symbols [-arch=amd64] [-version=10.0.19041] [-symbol_server=https//msdl.microsoft.com/download/symbols]

Requirements:
    pip install pefile requests