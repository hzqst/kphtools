#!/usr/bin/env python3
"""
File Upload Server for KPH Dynamic Data

HTTP server that handles file uploads, validates PE files and digital signatures,
and stores files in the symbol directory structure.

Usage:
    python upload_server.py -symboldir=C:/Symbols [-port=8000]
    
    Or:
    python upload_server.py -symboldir C:/Symbols -port 8000

Requirements:
    pip install pefile signify
"""

import os
import sys
import argparse
import hashlib
import http.server
import socketserver
from io import BytesIO
import re

try:
    import pefile
    from signify.authenticode.signed_file.pe import SignedPEFile
    from signify.authenticode.verification_result import VerificationError
except ImportError as e:
    error_name = getattr(e, 'name', str(e).split("'")[1] if "'" in str(e) else 'unknown')
    print(f"Error: Missing required dependency: {error_name}")
    print("Please install required packages: pip install pefile signify")
    sys.exit(1)


MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
UPLOAD_DIR = 'uploads'


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="HTTP server that handles file uploads, validates PE files and digital signatures"
    )
    parser.add_argument(
        "-symboldir",
        required=True,
        help="Directory to store uploaded files"
    )
    parser.add_argument(
        "-port",
        type=int,
        default=8000,
        help="Port to listen on (default: 8000)"
    )
    
    args = parser.parse_args()
    
    # Validate required arguments
    if not args.symboldir:
        parser.error("-symboldir cannot be empty")
    
    return args


def verify_pe_file(file_data):
    """
    Verify PE file and extract information.
    
    Args:
        file_data: Bytes data of the PE file
        
    Returns:
        Dictionary with file_name, file_version, arch, or None if validation fails
    """
    try:
        # Parse PE file from memory
        pe = pefile.PE(data=file_data)
        
        # Extract FileInfo
        file_description = None
        original_filename = None
        file_version = None
        
        if hasattr(pe, 'FileInfo') and pe.FileInfo:
            for fileinfo in pe.FileInfo:
                if fileinfo.Key == b'StringFileInfo':
                    for st in fileinfo.StringTable:
                        for key, value in st.entries.items():
                            if key == b'FileDescription':
                                file_description = value.decode('utf-8')
                            elif key == b'OriginalFilename':
                                original_filename = value.decode('utf-8')
                            elif key == b'FileVersion':
                                file_version = value.decode('utf-8')
        
        # Verify FileDescription
        if file_description != 'NT Kernel & System':
            return None
        
        # Check required fields
        if not original_filename or not file_version:
            return None
        
        # Determine architecture
        machine = pe.FILE_HEADER.Machine
        if machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            arch = 'x86'
        elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            arch = 'amd64'
        elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']:
            arch = 'arm64'
        else:
            return None
        
        pe.close()
        
        return {
            'file_name': original_filename,
            'file_version': file_version,
            'arch': arch
        }
        
    except pefile.PEFormatError:
        return None
    except Exception as e:
        print(f"Error parsing PE file: {e}")
        return None


def verify_signature(file_data):
    """
    Verify Authenticode digital signature.
    
    Args:
        file_data: Bytes data of the PE file
        
    Returns:
        True if signature is valid and matches requirements, False otherwise
    """
    try:
        # Create SignedPEFile from bytes
        file_io = BytesIO(file_data)
        signed_pe = SignedPEFile(file_io)
        
        # Verify the signature - this will raise VerificationError if invalid
        try:
            signed_pe.verify()
        except VerificationError:
            return False
        
        # Check signer and issuer from embedded signatures
        for signature in signed_pe.iter_embedded_signatures():
            signer_info = signature.signer_info
            
            # Get signer certificate - try different ways to access certificates
            signer_cert = None
            if hasattr(signer_info, 'certificates') and signer_info.certificates:
                signer_cert = signer_info.certificates[0]
            elif hasattr(signer_info, 'certificate'):
                signer_cert = signer_info.certificate
            
            if not signer_cert:
                continue
            
            # Extract signer name (subject CN) - try multiple methods
            signer_name = None
            if hasattr(signer_cert, 'subject'):
                subject = signer_cert.subject
                # Try common_name attribute
                if hasattr(subject, 'common_name'):
                    signer_name = subject.common_name
                # Try native representation
                elif hasattr(subject, 'native'):
                    subject_native = subject.native
                    if isinstance(subject_native, dict):
                        # Look for common_name in various formats
                        for attr in ['common_name', 'CN', '2.5.4.3', 'commonName']:
                            if attr in subject_native:
                                signer_name = subject_native[attr]
                                break
                    elif isinstance(subject_native, str):
                        signer_name = subject_native
                # Try to get from string representation
                elif hasattr(subject, '__str__'):
                    subject_str = str(subject)
                    # Try to extract CN from string like "CN=Microsoft Windows, ..."
                    if 'CN=' in subject_str:
                        cn_part = subject_str.split('CN=')[1].split(',')[0].strip()
                        signer_name = cn_part
            
            # Extract issuer name - try multiple methods
            issuer_name = None
            if hasattr(signer_cert, 'issuer'):
                issuer = signer_cert.issuer
                # Try common_name attribute
                if hasattr(issuer, 'common_name'):
                    issuer_name = issuer.common_name
                # Try native representation
                elif hasattr(issuer, 'native'):
                    issuer_native = issuer.native
                    if isinstance(issuer_native, dict):
                        # Look for common_name in various formats
                        for attr in ['common_name', 'CN', '2.5.4.3', 'commonName']:
                            if attr in issuer_native:
                                issuer_name = issuer_native[attr]
                                break
                    elif isinstance(issuer_native, str):
                        issuer_name = issuer_native
                # Try to get from string representation
                elif hasattr(issuer, '__str__'):
                    issuer_str = str(issuer)
                    # Try to extract CN from string like "CN=Microsoft Windows Production PCA 2011, ..."
                    if 'CN=' in issuer_str:
                        cn_part = issuer_str.split('CN=')[1].split(',')[0].strip()
                        issuer_name = cn_part
            
            # Verify signer and issuer
            if signer_name == 'Microsoft Windows' and issuer_name == 'Microsoft Windows Production PCA 2011':
                return True
        
        return False
        
    except VerificationError:
        return False
    except Exception as e:
        # Don't print error in production, just return False
        return False


def parse_multipart_form_data(rfile, content_type, content_length):
    """
    Parse multipart/form-data without using deprecated cgi module.
    
    Args:
        rfile: File-like object to read from
        content_type: Content-Type header value
        content_length: Content-Length header value
        
    Returns:
        Dictionary mapping field names to file objects with filename and file attributes
    """
    # Extract boundary from Content-Type
    boundary_match = re.search(r'boundary=([^;]+)', content_type)
    if not boundary_match:
        raise ValueError("No boundary found in Content-Type")
    
    boundary = boundary_match.group(1).strip('"')
    boundary_bytes = boundary.encode('ascii')
    delimiter = b'--' + boundary_bytes
    end_delimiter = delimiter + b'--'
    
    # Read all data
    data = rfile.read(content_length)
    
    # Remove trailing boundary end marker if present
    if data.endswith(end_delimiter):
        data = data[:-len(end_delimiter)]
    elif data.endswith(end_delimiter + b'\r\n'):
        data = data[:-len(end_delimiter) - 2]
    elif data.endswith(end_delimiter + b'\n'):
        data = data[:-len(end_delimiter) - 1]
    
    # Split by delimiter
    parts = data.split(delimiter)
    
    form_data = {}
    
    for part in parts:
        # Remove leading/trailing whitespace and newlines
        part = part.strip(b'\r\n')
        if not part:
            continue
        
        # Split headers and body
        if b'\r\n\r\n' in part:
            headers_raw, body = part.split(b'\r\n\r\n', 1)
        elif b'\n\n' in part:
            headers_raw, body = part.split(b'\n\n', 1)
        else:
            continue
        
        # Parse headers
        headers = {}
        for line in headers_raw.split(b'\n'):
            line = line.strip()
            if b':' in line:
                key, value = line.split(b':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Extract Content-Disposition
        content_disposition = headers.get(b'content-disposition', b'').decode('utf-8', errors='ignore')
        
        # Extract field name and filename
        name_match = re.search(r'name="([^"]+)"', content_disposition)
        filename_match = re.search(r'filename="([^"]+)"', content_disposition)
        
        if name_match:
            field_name = name_match.group(1)
            filename = filename_match.group(1) if filename_match else None
            
            # Create a file-like object
            class FileItem:
                def __init__(self, data, filename):
                    self.filename = filename
                    self.file = BytesIO(data)
            
            form_data[field_name] = FileItem(body.rstrip(b'\r\n'), filename)
    
    return form_data


def save_file(file_data, file_name, file_version, arch, symboldir):
    """
    Save file to target directory.
    
    Args:
        file_data: Bytes data of the file
        file_name: Original filename
        file_version: File version
        arch: Architecture (x86/amd64/arm64)
        symboldir: Base symbol directory
        
    Returns:
        Tuple of (success: bool, message: str, status_code: int)
    """
    # Build target path: {symboldir}/{arch}/{FileName}.{FileVersion}/{FileName}
    target_dir = os.path.join(symboldir, arch, f"{file_name}.{file_version}")
    target_path = os.path.join(target_dir, file_name)
    
    # Check if file already exists
    if os.path.exists(target_path):
        # Compare file contents
        with open(target_path, 'rb') as f:
            existing_data = f.read()
        
        existing_hash = hashlib.sha256(existing_data).hexdigest()
        new_hash = hashlib.sha256(file_data).hexdigest()
        
        if existing_hash == new_hash:
            return (True, "File already exists and is identical", 200)
        else:
            return (False, "File already exists with different content", 409)
    
    # Create directory if needed
    try:
        os.makedirs(target_dir, exist_ok=True)
    except OSError as e:
        return (False, f"Failed to create directory: {e}", 500)
    
    # Save file
    try:
        with open(target_path, 'wb') as f:
            f.write(file_data)
        return (True, "File uploaded successfully", 200)
    except OSError as e:
        return (False, f"Failed to save file: {e}", 500)


class UploadHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for file uploads."""
    
    def __init__(self, *args, symboldir=None, **kwargs):
        self.symboldir = symboldir
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        """Handle POST requests to /upload."""
        if self.path != '/upload':
            self.send_error(404, "Not Found")
            return
        
        # Check content length
        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return
        
        if content_length > MAX_FILE_SIZE:
            self.send_error(413, "File too large (max 20MB)")
            return
        
        if content_length == 0:
            self.send_error(400, "No file data")
            return
        
        # Check Content-Type
        content_type = self.headers.get('Content-Type', '')
        if not content_type.startswith('multipart/form-data'):
            self.send_error(400, "Content-Type must be multipart/form-data")
            return
        
        # Parse multipart form data
        try:
            form = parse_multipart_form_data(self.rfile, content_type, content_length)
        except Exception as e:
            self.send_error(400, f"Failed to parse form data: {e}")
            return
        
        # Get uploaded file
        if 'file' not in form:
            self.send_error(400, "No file in request")
            return
        
        file_item = form['file']
        if not file_item.filename:
            self.send_error(400, "No filename provided")
            return
        
        # Read file data
        try:
            file_data = file_item.file.read()
        except Exception as e:
            self.send_error(400, f"Failed to read file data: {e}")
            return
        
        # Verify file size matches Content-Length
        if len(file_data) > MAX_FILE_SIZE:
            self.send_error(413, "File too large (max 20MB)")
            return
        
        # Verify PE file and extract information
        pe_info = verify_pe_file(file_data)
        if not pe_info:
            self.send_error(400, "Invalid PE file or FileDescription does not match 'NT Kernel & System'")
            return
        
        # Verify digital signature
        if not verify_signature(file_data):
            self.send_error(400, "Digital signature verification failed or does not match requirements")
            return
        
        # Save file
        success, message, status_code = save_file(
            file_data,
            pe_info['file_name'],
            pe_info['file_version'],
            pe_info['arch'],
            self.symboldir
        )
        
        if success:
            self.send_response(status_code)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(message.encode('utf-8'))
        else:
            self.send_error(status_code, message)
    
    def log_message(self, format, *args):
        """Override to customize log format."""
        sys.stderr.write("%s - - [%s] %s\n" %
                        (self.address_string(),
                         self.log_date_time_string(),
                         format % args))


def main():
    """Main entry point."""
    args = parse_args()
    
    symboldir = args.symboldir
    port = args.port
    
    # Validate symbol directory
    if not os.path.exists(symboldir):
        try:
            os.makedirs(symboldir, exist_ok=True)
        except OSError as e:
            print(f"Error: Cannot create symbol directory: {e}")
            sys.exit(1)
    
    # Ensure upload directory exists
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    print(f"Symbol directory: {symboldir}")
    print(f"Upload directory: {UPLOAD_DIR}")
    print(f"Max file size: {MAX_FILE_SIZE / (1024 * 1024)}MB")
    print(f"Starting server on port {port}...")
    print(f"Upload endpoint: http://localhost:{port}/upload")
    
    # Create handler with symboldir parameter
    def handler_factory(*args, **kwargs):
        return UploadHandler(*args, symboldir=symboldir, **kwargs)
    
    # Start server
    try:
        with socketserver.TCPServer(("", port), handler_factory) as httpd:
            print(f"Server started. Press Ctrl+C to stop.")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except OSError as e:
        print(f"Error: Failed to start server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

