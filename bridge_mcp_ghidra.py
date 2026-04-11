# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def safe_post_json(endpoint: str, json_data) -> str:
    """
    Perform a POST request with a JSON body.
    """
    import json
    try:
        url = urljoin(ghidra_server_url, endpoint)
        body = json.dumps(json_data) if not isinstance(json_data, str) else json_data
        response = requests.post(url, data=body.encode("utf-8"),
                                 headers={"Content-Type": "application/json"},
                                 timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def disassemble_region(address: str, length: int = 0x100, max_instructions: int = 512) -> list:
    """
    Disassemble a raw address range without requiring a function definition.
    """
    return safe_get("disassemble_region", {
        "address": address,
        "length": length,
        "max_instructions": max_instructions,
    })

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def clear_data(address: str, size: int = None) -> str:
    """
    Clear (undefine) data at an address, reverting bytes to undefined state.
    If size is omitted, clears the single data item at that address.
    """
    data = {"address": address}
    if size is not None:
        data["size"] = str(size)
    return safe_post("clear_data", data)

@mcp.tool()
def define_data(address: str, data_type: str, label: str = None) -> str:
    """
    Create a data definition at an address. Supported types: byte, word, dword, qword,
    float, double, pointer, char, or any type in the data type manager.
    Optionally assign a label/symbol name.
    """
    data = {"address": address, "data_type": data_type}
    if label:
        data["label"] = label
    return safe_post("define_data", data)

@mcp.tool()
def create_array(address: str, base_type: str, dimensions: list[int], label: str = None) -> str:
    """
    Create an array data definition at an address.
    Example: base_type="ushort", dimensions=[12, 27] creates ushort[12][27].
    """
    dims = ",".join(str(int(d)) for d in dimensions)
    data = {
        "address": address,
        "base_type": base_type,
        "dimensions": dims,
    }
    if label:
        data["label"] = label
    return safe_post("create_array", data)

@mcp.tool()
def define_data_batch(items: list[dict]) -> str:
    """
    Create multiple data definitions in a single transaction.
    Each item: {"address": "0x...", "data_type": "dword", "label": "optional_name"}
    """
    return safe_post_json("define_data_batch", items)

@mcp.tool()
def read_bytes(address: str, length: int) -> str:
    """
    Read raw bytes from memory at a given address. Returns hex-encoded string.
    """
    lines = safe_get("read_bytes", {"address": address, "length": length})
    return lines[0] if lines else ""

@mcp.tool()
def get_data_at(address: str) -> str:
    """
    Get detailed info about the data item at a specific address:
    type, size, label, value, and containing item info.
    """
    return "\n".join(safe_get("get_data_at", {"address": address}))

@mcp.tool()
def batch_rename_functions(renames: list[dict]) -> str:
    """
    Rename multiple functions in one transaction.
    Each item: {"address": "0x...", "new_name": "MyFunction"}
    """
    return safe_post_json("batch_rename_functions", renames)

@mcp.tool()
def batch_set_comments(comments: list[dict], comment_type: str = "decompiler") -> str:
    """
    Set multiple comments in one transaction.
    comment_type: "decompiler" (PRE_COMMENT) or "disassembly" (EOL_COMMENT).
    Each comment: {"address": "0x...", "comment": "text"}
    """
    return safe_post_json("batch_set_comments", {
        "comment_type": comment_type,
        "comments": comments
    })

@mcp.tool()
def create_label(address: str, name: str, namespace: str = None) -> str:
    """
    Create a label/symbol at any address (code, data, or undefined bytes).
    """
    data = {"address": address, "name": name}
    if namespace:
        data["namespace"] = namespace
    return safe_post("create_label", data)

@mcp.tool()
def create_function(address: str, name: str = None, use_auto_body: bool = False, force_recreate: bool = False) -> str:
    """
    Create a function at an address.
    - address: function entry address
    - name: optional user-defined function name
    - use_auto_body: if true, attempt to discover function body automatically
    - force_recreate: if true, remove any existing function at entry address first
    """
    data = {"address": address}
    if name:
        data["name"] = name
    data["use_auto_body"] = str(use_auto_body).lower()
    data["force_recreate"] = str(force_recreate).lower()
    return safe_post("create_function", data)

@mcp.tool()
def delete_function(address: str) -> str:
    """
    Delete a function at the given address, or the containing function.
    """
    return safe_post("delete_function", {"address": address})

@mcp.tool()
def create_enum(name: str, values: list[dict], size: int = 4) -> str:
    """
    Create an enum data type. Each value: {"name": "MEMBER_NAME", "value": 0}
    """
    return safe_post_json("create_enum", {
        "name": name,
        "size": size,
        "values": values
    })

@mcp.tool()
def delete_enum(name: str) -> str:
    """
    Delete an enum datatype by exact name.
    """
    return safe_post("delete_enum", {"name": name})

@mcp.tool()
def create_struct(name: str, fields: list[dict]) -> str:
    """
    Create a structure data type.
    Each field: {"name": "field_name", "type": "int", "size": 4}
    If size is omitted, the type's natural size is used.
    """
    return safe_post_json("create_struct", {
        "name": name,
        "fields": fields
    })

@mcp.tool()
def apply_struct(address: str, struct_name: str) -> str:
    """
    Apply a previously created struct type at a memory address.
    Clears existing data at the address range and stamps the struct.
    """
    return safe_post("apply_struct", {"address": address, "struct_name": struct_name})

@mcp.tool()
def list_memory_blocks(offset: int = 0, limit: int = 200) -> list:
    """
    List memory blocks with range, permissions, mapping, and overlay metadata.
    """
    return safe_get("list_memory_blocks", {"offset": offset, "limit": limit})

@mcp.tool()
def create_byte_mapped_block(
    name: str,
    start: str,
    mapped_start: str,
    length: int,
    overlay: bool = True,
    read: bool = True,
    write: bool = False,
    execute: bool = True,
    comment: str = None,
    source_name: str = None,
    is_volatile: bool = False,
    artificial: bool = False,
) -> str:
    """
    Create a byte-mapped memory block. Useful for runtime-window overlays.
    """
    data = {
        "name": name,
        "start": start,
        "mapped_start": mapped_start,
        "length": str(length),
        "overlay": str(overlay).lower(),
        "read": str(read).lower(),
        "write": str(write).lower(),
        "execute": str(execute).lower(),
        "volatile": str(is_volatile).lower(),
        "artificial": str(artificial).lower(),
    }
    if comment is not None:
        data["comment"] = comment
    if source_name is not None:
        data["source_name"] = source_name
    return safe_post("create_byte_mapped_block", data)

@mcp.tool()
def set_memory_block_permissions(block: str, read: bool, write: bool, execute: bool) -> str:
    """
    Set read/write/execute permissions on a memory block by name or address.
    """
    return safe_post("set_memory_block_permissions", {
        "block": block,
        "read": str(read).lower(),
        "write": str(write).lower(),
        "execute": str(execute).lower(),
    })

@mcp.tool()
def set_memory_block_metadata(
    block: str,
    comment: str = None,
    source_name: str = None,
    is_volatile: bool = None,
    artificial: bool = None,
) -> str:
    """
    Update memory block metadata (comment/source/volatile/artificial) by block name or address.
    """
    data = {"block": block}
    if comment is not None:
        data["comment"] = comment
    if source_name is not None:
        data["source_name"] = source_name
    if is_volatile is not None:
        data["volatile"] = str(is_volatile).lower()
    if artificial is not None:
        data["artificial"] = str(artificial).lower()
    return safe_post("set_memory_block_metadata", data)

@mcp.tool()
def delete_memory_block(block: str) -> str:
    """
    Delete a memory block by name or address.
    """
    return safe_post("delete_memory_block", {"block": block})

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

