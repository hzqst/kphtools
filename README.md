## Toolkits for KPH Dynamic Data

[kphdyn.xml](https://github.com/winsiderss/systeminformer/blob/master/kphlib/kphdyn.xml).

Requirements:

Python packages:
```bash
pip install pefile requests signify
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

**Troubleshooting:** If you encounter `LibraryNotFoundError: Error detecting the version of libcrypto`:
1. Ensure `libssl-dev` (or `openssl-devel`) is installed (not just `openssl`)
2. Upgrade `oscrypto` library (especially important for OpenSSL 3.x):
   ```bash
   pip install --upgrade oscrypto
   # or upgrade all dependencies:
   pip install --upgrade -r requirements.txt
   ```
3. Clear Python cache and reinstall if needed:
   ```bash
   find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
   pip uninstall -y oscrypto signify
   pip install --no-cache-dir signify
   ```

## Download PE & Symbol listed in kphdyn.xml

Downloads PE files and their corresponding PDB symbol files from Microsoft Symbol Server
based on entries from `kphdyn.xml`

Usage, [] for optional:

```
python download_symbols.py -xml="path/to/kphdyn.xml" -symboldir="C:/Symbols" [-arch=amd64] [-version=10.0.10240.16393] [-symbol_server="https//msdl.microsoft.com/download/symbols"]
```

Files downloaded:

```
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\ntoskrnl.exe
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\ntkrnlmp.pdb
...others
```

## Adding new symbol to kphdyn.xml

```
python update_symbols.py -xml="path/to/kphdyn.xml" -symbol="EPROCESS->Protection" -symname="EpProtection"
```

Adds offset with `EpProtection` to `kphdyn.xml`

```
<fields id="15">
        //......others
        <field value="0x0672" name="EpProtection" />
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

Usage, [] for optional:

```
python upload_server.py -symboldir="C:/Symbols" [-port=8000]
```

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

Checks if your ntoskrnl already exists:

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

Upload your ntoskrnl to localhost server:

```
curl -X POST -F "file=@C:/Windows/System32/ntoskrnl.exe" http://localhost:8000/upload
```

* File size limit: 20MB
* If the target file already exists, it will not be overwritten
* Both "multipart/form-data" and "application/octet-stream" are supported
* Header "X-File-Compressed: gzip" supported, client should gzip the ntoskrnl payload before uploading.