#!/usr/bin/env python3
"""
Add ntoskrnl.exe entry from VirusTotal API to kphdyn.xml

This script fetches file information from VirusTotal API and adds a new entry
to the kphdyn.xml file with the correct format and placement.

Usage:
    python add_ntoskrnl_from_virustotal.py -xml=path/to/kphdyn.xml -md5=md5_hash -sha256=sha256_hash -apikey=your_api_key
"""

import argparse
import hashlib
import os
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
import requests


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Add ntoskrnl.exe entry from VirusTotal API to kphdyn.xml"
    )
    parser.add_argument(
        "-xml",
        required=True,
        help="Path to the kphdyn.xml file"
    )
    parser.add_argument(
        "-md5",
        required=False,
        help="MD5 hash of the file"
    )
    parser.add_argument(
        "-sha256",
        required=False,
        help="SHA256 hash of the file"
    )
    parser.add_argument(
        "-apikey",
        required=True,
        help="VirusTotal API key"
    )

    args = parser.parse_args()

    # Validate that at least one hash is provided
    if not args.md5 and not args.sha256:
        parser.error("Either -md5 or -sha256 must be provided")

    return args


def get_virustotal_data(md5=None, sha256=None, apikey=None):
    """
    Fetch file information from VirusTotal API.

    Args:
        md5: MD5 hash of the file
        sha256: SHA256 hash of the file
        apikey: VirusTotal API key

    Returns:
        Dictionary with the file information, or None if failed
    """
    # Determine which hash to use (prefer SHA256)
    hash_to_use = sha256 if sha256 else md5
    hash_type = "sha256" if sha256 else "md5"

    url = f"https://www.virustotal.com/api/v3/files/{hash_to_use}"
    headers = {
        "x-apikey": apikey
    }

    try:
        print(f"Fetching file information from VirusTotal using {hash_type}: {hash_to_use}")
        response = requests.get(url, headers=headers, timeout=60)
        response.raise_for_status()

        data = response.json()
        return data.get("data", {}).get("attributes", {})

    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from VirusTotal: {e}")
        return None
    except ValueError as e:
        print(f"Error parsing JSON response: {e}")
        return None


def extract_file_info(vt_data):
    """
    Extract required information from VirusTotal data.

    Args:
        vt_data: Dictionary from VirusTotal API

    Returns:
        Dictionary with extracted info or None if failed
    """
    try:
        result = {}

        # Extract timestamp
        creation_date = vt_data.get("creation_date")
        if not creation_date:
            print("Error: creation_date not found in VirusTotal data")
            return None
        result["timestamp"] = f"0x{creation_date:x}"

        # Extract size from sections
        sections = vt_data.get("pe_info", {}).get("sections", [])
        if not sections:
            print("Error: No sections found in PE info")
            return None

        # Find the last section (usually .reloc)
        last_section = sections[-1]
        virtual_address = last_section.get("virtual_address", 0)
        virtual_size = last_section.get("virtual_size", 0)

        # Calculate SizeOfImage and align to 4K page
        size_of_image = virtual_address + virtual_size
        # Align up to 4K (0x1000)
        page_size = 0x1000
        aligned_size = ((size_of_image + page_size - 1) // page_size) * page_size
        result["size"] = f"0x{aligned_size:08x}"

        # Extract architecture from magic
        magic = vt_data.get("magic", "")
        if "x86-64" in magic:
            result["arch"] = "amd64"
        elif "Aarch64" in magic:
            result["arch"] = "arm64"
        elif "x86" in magic:
            result["arch"] = "x86"
        else:
            print(f"Error: Unknown architecture in magic string: {magic}")
            return None

        # Extract file version
        signature_info = vt_data.get("signature_info", {})
        file_version = signature_info.get("file version", "")
        if file_version:
            # Remove anything in parentheses and trim
            if "(" in file_version:
                file_version = file_version[:file_version.find("(")].strip()
            result["version"] = file_version
        else:
            print("Error: file version not found in signature info")
            return None

        # Extract sha256
        sha256 = vt_data.get("sha256", "")
        if sha256:
            result["sha256"] = sha256
        else:
            print("Error: sha256 not found in VirusTotal data")
            return None

        return result

    except Exception as e:
        print(f"Error extracting file info: {e}")
        return None


def parse_version(version_str):
    """
    Parse version string into comparable tuple.

    Args:
        version_str: Version string like "10.0.16299.15"

    Returns:
        Tuple of integers for comparison
    """
    try:
        parts = version_str.split(".")
        return tuple(int(part) for part in parts)
    except:
        return (0, 0, 0, 0)


def find_insertion_point(root, new_version, arch):
    """
    Find the correct insertion point in XML based on version.

    Args:
        root: XML root element
        new_version: New version string
        arch: Architecture (amd64/arm64)

    Returns:
        Tuple of (insertion_index, field_id) or (None, None) if not found
    """
    new_version_tuple = parse_version(new_version)
    best_ntkrla57_index = None
    best_ntoskrnl_index = None
    best_ntoskrnl_id = None

    # Find all data elements with matching architecture
    data_elements = []
    for i, data_elem in enumerate(root):
        if data_elem.tag == "data" and data_elem.get("arch") == arch:
            data_elements.append((i, data_elem))

    # Find the best candidates
    for i, data_elem in data_elements:
        version = data_elem.get("version")
        file_name = data_elem.get("file")

        if not version:
            continue

        version_tuple = parse_version(version)

        # Only consider versions smaller than new version
        if version_tuple >= new_version_tuple:
            continue

        # Track the best ntkrla57.exe candidate
        if file_name == "ntkrla57.exe":
            if best_ntkrla57_index is None or version_tuple > parse_version(root[best_ntkrla57_index].get("version", "0.0.0.0")):
                best_ntkrla57_index = i

        # Track the best ntoskrnl.exe candidate (for field ID)
        elif file_name == "ntoskrnl.exe":
            if best_ntoskrnl_index is None or version_tuple > parse_version(root[best_ntoskrnl_index].get("version", "0.0.0.0")):
                best_ntoskrnl_index = i
                best_ntoskrnl_id = data_elem.text

    # Prefer ntkrla57.exe insertion point if it exists
    if best_ntkrla57_index is not None:
        return best_ntkrla57_index, best_ntoskrnl_id
    # Fall back to ntoskrnl.exe insertion point
    elif best_ntoskrnl_index is not None:
        return best_ntoskrnl_index, best_ntoskrnl_id
    else:
        return None, None


def format_xml(elem, level=0):
    """
    Add indentation and newlines to XML element for pretty printing.

    Args:
        elem: XML element
        level: Current indentation level
    """
    indent = "    "  # 4 spaces for indentation
    i = "\n" + level * indent

    if len(elem):
        # If element has children
        if not elem.text or not elem.text.strip():
            elem.text = i + indent
        for child in elem:
            format_xml(child, level + 1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        # If element has no children
        if not elem.tail or not elem.tail.strip():
            elem.tail = i


def add_entry_to_xml(xml_path, file_info):
    """
    Add new entry to XML file.

    Args:
        xml_path: Path to XML file
        file_info: Dictionary with file information

    Returns:
        True if successful, False otherwise
    """
    try:
        # Parse XML
        tree = ET.parse(xml_path)
        root = tree.getroot()

        # Check if entry already exists
        for data_elem in root:
            if (data_elem.tag == "data" and
                data_elem.get("arch") == file_info["arch"] and
                data_elem.get("version") == file_info["version"] and
                data_elem.get("file") == "ntoskrnl.exe"):

                print(f"Entry already exists for {file_info['version']} ({file_info['arch']})")
                print(f"  Existing hash: {data_elem.get('hash')}")
                print(f"  Existing timestamp: {data_elem.get('timestamp')}")
                print(f"  Existing size: {data_elem.get('size')}")
                print(f"  New hash: {file_info['sha256']}")
                print("No changes made.")
                return True

        # Find insertion point
        insert_index, field_id = find_insertion_point(root, file_info["version"], file_info["arch"])

        if insert_index is None:
            print(f"Error: Could not find suitable insertion point for version {file_info['version']}")
            return False

        # Create new data element
        new_data = ET.Element("data")
        new_data.set("arch", file_info["arch"])
        new_data.set("version", file_info["version"])
        new_data.set("file", "ntoskrnl.exe")
        new_data.set("hash", file_info["sha256"])
        new_data.set("timestamp", file_info["timestamp"])
        new_data.set("size", file_info["size"])
        new_data.text = field_id

        # Insert after the found element
        root.insert(insert_index + 1, new_data)

        # Format XML for pretty printing
        format_xml(root)

        # Create backup
        backup_path = xml_path + ".backup"
        tree.write(backup_path, encoding="utf-8", xml_declaration=True)
        print(f"Created backup: {backup_path}")

        # Save updated XML with formatting
        tree.write(xml_path, encoding="utf-8", xml_declaration=True)

        # Get the reference element for insertion point info
        ref_elem = root[insert_index]
        ref_version = ref_elem.get("version")
        ref_file = ref_elem.get("file")

        print(f"Successfully added entry for {file_info['version']} ({file_info['arch']})")
        print(f"  Inserted after: {ref_file} version {ref_version}")
        print(f"  Hash: {file_info['sha256']}")
        print(f"  Timestamp: {file_info['timestamp']}")
        print(f"  Size: {file_info['size']}")
        print(f"  Field ID: {field_id}")

        return True

    except Exception as e:
        print(f"Error updating XML file: {e}")
        return False


def main():
    """Main entry point."""
    args = parse_args()

    xml_path = args.xml
    md5 = args.md5
    sha256 = args.sha256
    apikey = args.apikey

    # Validate XML file exists
    if not os.path.exists(xml_path):
        print(f"Error: XML file not found: {xml_path}")
        sys.exit(1)

    print(f"XML file: {xml_path}")
    print(f"MD5: {md5}")
    print(f"SHA256: {sha256}")

    # Fetch data from VirusTotal
    vt_data = get_virustotal_data(md5, sha256, apikey)
    if not vt_data:
        print("Failed to fetch data from VirusTotal")
        sys.exit(1)

    # Extract required information
    file_info = extract_file_info(vt_data)
    if not file_info:
        print("Failed to extract required information from VirusTotal data")
        sys.exit(1)

    print(f"\nExtracted file information:")
    print(f"  Architecture: {file_info['arch']}")
    print(f"  Version: {file_info['version']}")
    print(f"  Timestamp: {file_info['timestamp']}")
    print(f"  Size: {file_info['size']}")
    print(f"  SHA256: {file_info['sha256']}")

    # Add entry to XML
    if not add_entry_to_xml(xml_path, file_info):
        print("Failed to add entry to XML file")
        sys.exit(1)

    print("\nOperation completed successfully!")


if __name__ == "__main__":
    main()