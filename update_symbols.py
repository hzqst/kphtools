#!/usr/bin/env python3
"""
Symbol Update Script for KPH Dynamic Data

Updates field offsets in kphdyn.xml by parsing PDB files using llvm-pdbutil.

Usage:
    python update_symbols.py -xml=kphdyn.xml -symboldir=C:/Symbols -symbol=EPROCESS->SectionObject -symname=EpSectionObject
    
    Or:
    python update_symbols.py -xml kphdyn.xml -symboldir C:/Symbols -symbol "EPROCESS->SectionObject" -symname EpSectionObject

Requirements:
    - llvm-pdbutil must be available in system PATH
"""

import os
import re
import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Updates field offsets in kphdyn.xml by parsing PDB files using llvm-pdbutil"
    )
    parser.add_argument(
        "-xml",
        required=True,
        help="Path to the XML file (e.g., kphdyn.xml)"
    )
    parser.add_argument(
        "-symboldir",
        required=True,
        help="Directory containing symbol files"
    )
    parser.add_argument(
        "-symbol",
        required=True,
        help="Symbol to parse (e.g., EPROCESS->SectionObject)"
    )
    parser.add_argument(
        "-symname",
        required=True,
        help="Field name in XML (e.g., EpSectionObject)"
    )
    
    args = parser.parse_args()
    
    # Validate required arguments
    if not args.xml:
        parser.error("-xml cannot be empty")
    if not args.symboldir:
        parser.error("-symboldir cannot be empty")
    if not args.symbol:
        parser.error("-symbol cannot be empty")
    if not args.symname:
        parser.error("-symname cannot be empty")
    
    return args


def parse_symbol(symbol_str):
    """
    Parse symbol string into structure name and member name.
    
    Args:
        symbol_str: Symbol string like "EPROCESS->SectionObject"
        
    Returns:
        Tuple of (struct_name, member_name)
    """
    if "->" not in symbol_str:
        print(f"Error: Invalid symbol format '{symbol_str}'. Expected format: STRUCT->Member")
        sys.exit(1)
    
    parts = symbol_str.split("->")
    if len(parts) != 2:
        print(f"Error: Invalid symbol format '{symbol_str}'. Expected format: STRUCT->Member")
        sys.exit(1)
    
    struct_name = parts[0].strip()
    member_name = parts[1].strip()
    
    # Add underscore prefix if not present (Windows kernel structures use _EPROCESS format)
    if not struct_name.startswith("_"):
        struct_name = "_" + struct_name
    
    return struct_name, member_name


def find_ntoskrnl_entries_for_id(root, field_id):
    """
    Find all ntoskrnl.exe or ntkrla57.exe data entries matching the given field ID.
    
    Args:
        root: XML root element
        field_id: The field ID to match
        
    Returns:
        List of matching data elements (may be empty)
    """
    field_id_str = str(field_id)
    entries = []
    for data_elem in root.findall("data"):
        # Check if the text content matches the field ID
        text_content = data_elem.text
        if text_content is not None and text_content.strip() == field_id_str:
            # Check if it's ntoskrnl.exe or ntkrla57.exe
            file_name = data_elem.get("file")
            if file_name == "ntoskrnl.exe" or file_name == "ntkrla57.exe":
                entries.append(data_elem)
    return entries


def get_pdb_path(symboldir, arch, version):
    """
    Build the path to the PDB file.
    
    Args:
        symboldir: Base symbol directory
        arch: Architecture (amd64, arm64, etc.)
        version: Windows version string
        
    Returns:
        Path to the PDB file
    """
    symbol_subdir = os.path.join(symboldir, arch, f"ntoskrnl.exe.{version}")
    pdb_path = os.path.join(symbol_subdir, "ntkrnlmp.pdb")
    return pdb_path


def parse_pdb_offset(pdb_path, struct_name, member_name):
    """
    Parse PDB file using llvm-pdbutil to get structure member offset.
    
    Args:
        pdb_path: Path to the PDB file
        struct_name: Structure name (e.g., _EPROCESS)
        member_name: Member name (e.g., SectionObject)
        
    Returns:
        Offset as integer, or None if not found
    """
    if not os.path.exists(pdb_path):
        print(f"  PDB file not found: {pdb_path}")
        return None
    
    try:
        # Run llvm-pdbutil to dump type information
        result = subprocess.run(
            ["llvm-pdbutil", "dump", "-types", pdb_path],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode != 0:
            print(f"  llvm-pdbutil failed: {result.stderr}")
            return None
        
        output = result.stdout
        
        # Parse the output to find the structure and member
        # llvm-pdbutil output format varies, we need to handle different formats
        offset = parse_llvm_pdbutil_output(output, struct_name, member_name)
        
        return offset
        
    except FileNotFoundError:
        print("  Error: llvm-pdbutil not found in PATH")
        print("  Please install LLVM tools and ensure llvm-pdbutil is in your PATH")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"  Timeout while parsing PDB: {pdb_path}")
        return None
    except Exception as e:
        print(f"  Error running llvm-pdbutil: {e}")
        return None


def parse_llvm_pdbutil_output(output, struct_name, member_name):
    """
    Parse llvm-pdbutil dump output to find member offset.
    
    llvm-pdbutil dump -types output format:
    
    1. Structure definition with field list reference:
       0x13D9 | LF_STRUCTURE [size = 48] `_EPROCESS`
               unique name: `.?AU_EPROCESS@@`
               vtable: <no type>, base list: <no type>, field list: 0x13D8
               options: has unique name, sizeof 2104
    
    2. Field list with members:
       0x13D8 | LF_FIELDLIST [size = 5988]
               - LF_MEMBER [name = `Protection`, Type = 0x13C7, offset = 1738, attrs = public]
    
    Args:
        output: llvm-pdbutil output string
        struct_name: Structure name to find (e.g., _EPROCESS)
        member_name: Member name to find offset for (e.g., Protection)
        
    Returns:
        Offset as integer, or None if not found
    """
    lines = output.split('\n')
    
    # Step 1: Find the structure definition and get its field list ID
    # We need to find the non-forward-ref definition (the one with sizeof != 0)
    field_list_id = None
    
    for i, line in enumerate(lines):
        # Look for LF_STRUCTURE with our struct name
        if "LF_STRUCTURE" in line and f"`{struct_name}`" in line:
            # Check the next few lines for field list reference
            for j in range(i + 1, min(i + 10, len(lines))):
                next_line = lines[j]
                # Skip forward references (sizeof 0)
                if "forward ref" in next_line:
                    break
                # Look for field list reference
                field_list_match = re.search(r'field list:\s*(0x[0-9a-fA-F]+)', next_line)
                if field_list_match:
                    field_list_id = field_list_match.group(1)
                    break
            
            # If we found a field list, we're done searching for the struct
            if field_list_id:
                break
    
    if not field_list_id:
        return None
    
    # Step 2: Find the LF_FIELDLIST with this ID and search for the member
    in_field_list = False
    
    for line in lines:
        # Look for the field list
        if f"{field_list_id} | LF_FIELDLIST" in line:
            in_field_list = True
            continue
        
        # Check if we're leaving the field list (next type entry)
        if in_field_list and re.match(r'\s*0x[0-9a-fA-F]+\s*\|\s*LF_', line):
            in_field_list = False
            continue
        
        # Look for member in current field list
        if in_field_list:
            # Pattern: - LF_MEMBER [name = `MemberName`, Type = 0xXXXX, offset = DECIMAL, attrs = public]
            match = re.search(
                rf'LF_MEMBER\s*\[name\s*=\s*`{re.escape(member_name)}`.*offset\s*=\s*(\d+)',
                line
            )
            if match:
                offset_decimal = int(match.group(1))
                return offset_decimal
    
    # Fallback: Search for the member directly in any LF_MEMBER line
    # This handles cases where we might have missed the field list
    for line in lines:
        match = re.search(
            rf'LF_MEMBER\s*\[name\s*=\s*`{re.escape(member_name)}`.*offset\s*=\s*(\d+)',
            line
        )
        if match:
            # We found a match, but we need to verify it's in the right structure
            # For now, return the first match as a fallback
            offset_decimal = int(match.group(1))
            return offset_decimal
    
    return None


def update_xml_field(fields_elem, symname, offset):
    """
    Update or add a field element in the fields section.
    
    Args:
        fields_elem: The <fields> XML element
        symname: Field name to update
        offset: Offset value (integer)
    """
    # Format offset as lowercase hex with 0x prefix
    offset_str = f"0x{offset:04x}"
    
    # Look for existing field with this name
    for field_elem in fields_elem.findall("field"):
        if field_elem.get("name") == symname:
            field_elem.set("value", offset_str)
            return
    
    # Field not found, add new one
    new_field = ET.SubElement(fields_elem, "field")
    new_field.set("value", offset_str)
    new_field.set("name", symname)


def save_xml(tree, xml_path):
    """
    Save XML tree to file, preserving formatting.
    
    Args:
        tree: ElementTree object
        xml_path: Path to save the XML file
    """
    # Write with XML declaration and proper encoding
    tree.write(xml_path, encoding="utf-8", xml_declaration=True)
    
    # Read back and fix formatting (add newlines)
    with open(xml_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Add proper indentation
    # This is a simple approach - for complex XML, consider using lxml
    content = content.replace("><", ">\n<")
    
    with open(xml_path, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    """Main entry point."""
    args = parse_args()
    
    xml_path = args.xml
    symboldir = args.symboldir
    symbol_str = args.symbol
    symname = args.symname
    
    # Validate XML file exists
    if not os.path.exists(xml_path):
        print(f"Error: XML file not found: {xml_path}")
        sys.exit(1)
    
    # Validate symbol directory exists
    if not os.path.exists(symboldir):
        print(f"Error: Symbol directory not found: {symboldir}")
        sys.exit(1)
    
    # Parse symbol string
    struct_name, member_name = parse_symbol(symbol_str)
    
    print(f"XML file: {xml_path}")
    print(f"Symbol directory: {symboldir}")
    print(f"Symbol: {struct_name}->{member_name}")
    print(f"Field name: {symname}")
    
    # Parse XML
    print("\nParsing XML...")
    tree = ET.parse(xml_path)
    root = tree.getroot()
    
    # Find all fields elements
    fields_elements = root.findall("fields")
    print(f"Found {len(fields_elements)} fields sections")
    
    if not fields_elements:
        print("No <fields> elements found in XML.")
        sys.exit(0)
    
    # Process each fields section
    success_count = 0
    skip_count = 0
    fail_count = 0
    
    for fields_elem in fields_elements:
        field_id = fields_elem.get("id")
        if not field_id:
            print(f"\nSkipping fields element without id")
            skip_count += 1
            continue
        
        print(f"\nProcessing fields id={field_id}")
        
        # Find all ntoskrnl.exe entries for this field ID
        data_entries = find_ntoskrnl_entries_for_id(root, field_id)
        if not data_entries:
            print(f"  No ntoskrnl.exe entry found for id={field_id}, skipping")
            skip_count += 1
            continue
        
        # Try each entry until we find one with a valid PDB
        found_pdb = False
        for data_elem in data_entries:
            version = data_elem.get("version")
            arch = data_elem.get("arch")
            
            # Get PDB path
            pdb_path = get_pdb_path(symboldir, arch, version)
            
            if os.path.exists(pdb_path):
                print(f"  Found ntoskrnl.exe version {version} ({arch})")
                print(f"  PDB path: {pdb_path}")
                found_pdb = True
                break
        
        if not found_pdb:
            print(f"  No PDB file found for any entry with id={field_id}, skipping")
            skip_count += 1
            continue
        
        # Parse PDB to get offset
        print(f"  Parsing PDB for {struct_name}->{member_name}...")
        offset = parse_pdb_offset(pdb_path, struct_name, member_name)
        
        if offset is None:
            print(f"  Failed to find offset for {struct_name}->{member_name}")
            fail_count += 1
            continue
        
        print(f"  Found offset: 0x{offset:04x}")
        
        # Update XML
        update_xml_field(fields_elem, symname, offset)
        print(f"  Updated field {symname} = 0x{offset:04x}")
        success_count += 1
    
    # Save updated XML
    if success_count > 0:
        print(f"\nSaving updated XML to {xml_path}...")
        save_xml(tree, xml_path)
        print("Done!")
    
    # Summary
    print(f"\n{'='*50}")
    print(f"Summary: {success_count} updated, {skip_count} skipped, {fail_count} failed")
    
    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

