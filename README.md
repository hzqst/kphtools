## Toolkits for KPH Dynamic Data

### Get kphdyn.xml

[kphdyn.xml](https://github.com/winsiderss/systeminformer/blob/master/kphlib/kphdyn.xml).

```bash
wget https://raw.githubusercontent.com/winsiderss/systeminformer/master/kphlib/kphdyn.xml
```

```bash
curl -O https://raw.githubusercontent.com/winsiderss/systeminformer/master/kphlib/kphdyn.xml
```

```powershell
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/winsiderss/systeminformer/master/kphlib/kphdyn.xml' -OutFile kphdyn.xml"
```

### Requirements

Python packages:
```bash
pip install -r requirements.txt --break-system-packages
```

System dependencies (for signify library, required on Linux):
- **Ubuntu/Debian:**
  ```bash
  sudo apt-get update
  sudo apt-get install -y libssl-dev
  ```
- **CentOS/RHEL/Fedora:**
  ```bash
  sudo yum install -y openssl-devel
  # or on newer versions:
  sudo dnf install -y openssl-devel
  ```

- **Fix oscrypto issue - Error detecting the version of libcrypto :**
```bash
  pip install -I git+https://github.com/wbond/oscrypto.git --break-system-packages
```

## Download PE & Symbol listed

Downloads PE files and their corresponding PDB symbol files from Microsoft Symbol Server
based on entries from `kphdyn.xml`

### Usage, [] for optional

```bash
python download_symbols.py -xml="path/to/kphdyn.xml" -symboldir="C:/Symbols" [-arch=amd64] [-version=10.0.10240.16393] [-symbol_server="https//msdl.microsoft.com/download/symbols"]
```

### Possible environment variables

```bash
export KPHTOOLS_XML="path/to/kphdyn.xml"
export KPHTOOLS_SYMBOLDIR="C:/Symbols"
```

```bash
set KPHTOOLS_XML=path/to/kphdyn.xml
set KPHTOOLS_SYMBOLDIR=C:/Symbols
```

### Expected downloads

```
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\ntoskrnl.exe
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\ntkrnlmp.pdb
...others
```

## Update symbols in kphdyn.xml

Updates field offsets in `kphdyn.xml` by parsing PDB files using `llvm-pdbutil`.

Also supports **syncfile mode** to scan symbol directory and add missing entries to XML.

### Requirements

- `llvm-pdbutil` must be available in system PATH (part of LLVM tools)
- `pefile` Python package required for syncfile mode (`pip install pefile`)

### Usage

**Normal mode** - Update symbol offsets from PDB files:
```bash
python update_symbols.py -xml="path/to/kphdyn.xml" -symboldir="C:/Symbols" -json="path/to/kphdyn.json"
```

**Syncfile mode** - Scan symbol directory and add missing entries:
```bash
python update_symbols.py -xml="path/to/kphdyn.xml" -symboldir="C:/Symbols" -syncfile
```

### Optional Arguments

- `-sha256`: Only process entries with this SHA256 hash value (case-insensitive)
- `-pdbutil`: Path to llvm-pdbutil executable (default: search in PATH)
- `-outxml`: Path to output XML file (default: overwrite input XML file)
- `-debug`: Enable debug logging for symbol parsing
- `-syncfile`: Sync PE files from symbol directory to XML (add missing entries)
- `-fast`: Fast mode for syncfile - only parse PE when entry is missing

### Examples

**Normal mode examples:**

Update and overwrite the original file:

```bash
python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -json="kphdyn.json"
```

Save to a different output file:

```bash
python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -json="kphdyn.json" -outxml="kphdyn_updated.xml"
```

Process only a specific SHA256 hash:

```bash
python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -json="kphdyn.json" -sha256="abc123..."
```

Use custom llvm-pdbutil path:

```bash
python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -json="kphdyn.json" -pdbutil="/path/to/llvm-pdbutil"
```

**Syncfile mode examples:**

Scan symbol directory and add missing entries:

```bash
python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -syncfile
```

Use fast mode (only parse PE when entry is missing):

```bash
python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -syncfile -fast
```

Save to a different output file:

```bash
python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -syncfile -outxml="kphdyn_updated.xml"
```

### Syncfile Mode Details

The syncfile mode scans the symbol directory for PE files (exe/dll/sys) and adds missing entries to the XML:

**How it works:**

1. Scans all PE files in the symbol directory (e.g., `C:/Symbols/amd64/ntoskrnl.exe.10.0.16299.551/ntoskrnl.exe`)
2. Extracts metadata from file path: `arch`, `file`, `version`
3. Checks if a matching `<data>` entry exists in XML (by arch + file + version)
4. If the entry doesn't exist:
   - Parses PE file to extract `hash` (SHA256), `timestamp`, and `size`
   - Finds the insertion position (after the closest smaller version)
   - Creates new entry with `fields id="0"` (not yet resolved)
5. Skips entries that already exist in XML

**Fast mode (`-fast`):**

In normal syncfile mode, all PE files are parsed upfront. With `-fast` flag, PE parsing is deferred until an entry is confirmed to be missing, which can significantly speed up the process when most entries already exist.

**Expected symbol directory structure:**

```text
C:/Symbols/
├── amd64/
│   ├── ntoskrnl.exe.10.0.16299.551/
│   │   ├── ntoskrnl.exe
│   │   └── ntkrnlmp.pdb
│   └── ntkrla57.exe.10.0.20348.4529/
│       ├── ntkrla57.exe
│       └── ntkrla57.pdb
└── arm64/
    └── ntoskrnl.exe.10.0.16299.1004/
        ├── ntoskrnl.exe
        └── ntkrnlmp.pdb
```

**Output example:**

```text
Scanning symbol directory: C:/Symbols
  Found 3071 PE files

[1457/3071] amd64/ntoskrnl.exe v10.0.19041.5070
  Entry missing, parsing PE...
  Added new entry after version 10.0.19041.5007

Summary: 2 added, 3069 skipped, 0 failed
```

### Configuration (kphdyn.json)

The JSON config file specifies which files to process and which symbols to extract:

```json
[
    {
        "file" : [ "ntoskrnl.exe", "ntkrla57.exe" ],
        "symbols": [
            {
                "name" : "EpObjectTable",
                "struct_offset" : "_EPROCESS->ObjectTable"
            },
            {
                "name" : "EpSectionObject",
                "struct_offset" : "_EPROCESS->SectionObject"
            }
        ]
    }
]
```

### Output

For each `<data>` entry matching the specified files, the script:
1. Parses the corresponding PDB file to extract all symbol offsets
2. Assigns a `<fields>` ID (reuses existing ID if offsets match exactly)
3. Updates the `<data>` entry to reference the correct `<fields>` ID
4. Removes orphan `<fields>` elements that are no longer referenced

```xml
<data arch="amd64" version="10.0.10240.16384" file="ntoskrnl.exe" ...>1</data>
<fields id="1">
    <field value="0x0418" name="EpObjectTable"/>
    <field value="0x03b8" name="EpSectionObject"/>
</fields>
```

## Add new ntoskrnl entry to kphdyn.xml with known MD5/SHA256

```
python add_ntoskrnl_from_virustotal.py -xml="path/to/kphdyn.xml" -md5=9F4D868D410F6D68D0A73C9139D754B0 -apikey="{YourAPIKey}"
```

A new entry :

`<data arch="amd64" version="10.0.26100.5067" file="ntoskrnl.exe" hash="eef546d98c2ee3c006756c47bad46c62157d6f43bc8204e2679d3895efbc33c2" timestamp="0x66ffa119" size="0x0144f000">25</data>`

will be added to `kphdyn.xml` if file with given has was found on virustotal.

* Get a valid api key from https://www.virustotal.com/

## HTTP server for collecting ntoskrnl.exe 

HTTP server that handles file uploads, validates PE files and digital signatures, and stores files in the symbol directory structure.

**Note:** On Linux systems (Ubuntu/Debian/CentOS), you must install OpenSSL development libraries before running this server. See Requirements section above.

The server will:
- Accept POST requests to `/upload` endpoint
- Validate uploaded files (must be PE files)
- Verify FileDescription must be "NT Kernel & System"
- Verify Authenticode signature (Signer must be "Microsoft Windows", Issuer must be "Microsoft Windows Production PCA 2011")
- Extract OriginalFilename and FileVersion from FileResource
- Determine architecture (x86/amd64/arm64) from PE header
- Store files to: `{symboldir}/{arch}/{FileName}.{FileVersion}/{FileName}`

Example:
- If `-symboldir="C:/Symbols"`, `arch=amd64`, `FileName=ntoskrnl.exe`, `FileVersion=10.0.22621.741`
- File will be stored at: `C:/Symbols/amd64/ntoskrnl.exe.10.0.22621.741/ntoskrnl.exe`

### Usage, [] for optional

```
python upload_server.py -symboldir="C:/Symbols" [-port=8000]
```

### Possible environment variables

```bash
export KPHTOOLS_SYMBOLDIR="C:/Symbols"
```

```bash
set KPHTOOLS_SYMBOLDIR=C:/Symbols
```

### API: Checks if your ntoskrnl already exists:

```
curl "http://localhost:8000/exists?filename=ntoskrnl.exe&arch=amd64&fileversion=10.0.26100.7462"
```

Found:
```
{"success": true, "message": "File existence checked", "filename": "ntoskrnl.exe", "arch": "amd64", "fileversion": "10.0.26100.7462", "exists": true, "path": "amd64/ntoskrnl.exe.10.0.26100.7462/ntoskrnl.exe", "file_size": 12993992}
```

Not found:
```
{"success": true, "message": "File existence checked", "filename": "ntoskrnl.exe", "arch": "amd64", "fileversion": "10.0.26100.7461", "exists": false, "path": "amd64/ntoskrnl.exe.10.0.26100.7461/ntoskrnl.exe"}
```

### API: Upload your ntoskrnl to localhost server:

```
curl -X POST -F "file=@C:/Windows/System32/ntoskrnl.exe" http://localhost:8000/upload
```

* File size limit: 20MB
* If the target file already exists, it will not be overwritten
* Both "multipart/form-data" and "application/octet-stream" are supported
* Header "X-File-Compressed: gzip" supported, client should gzip the ntoskrnl payload before uploading.

### API: Healthy Check

```
curl "http://localhost:8000/health"
```

```
{"status": "healthy"}
```