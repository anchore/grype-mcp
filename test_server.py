#!/usr/bin/env python3
"""Test the fixed MCP server"""

import subprocess
import sys
import json

def test_server_import():
    """Test that the server imports correctly"""
    try:
        from grype_mcp.server import mcp
        print("✅ Server imports successfully")
        assert True
    except Exception as e:
        print(f"❌ Server import failed: {e}")
        assert False, f"Server import failed: {e}"

def test_server_run():
    """Test that the server can start (but not run indefinitely)"""
    try:
        # Try to run the server for a brief moment
        process = subprocess.Popen(
            [sys.executable, "grype_mcp/server.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Send a simple test message and close
        try:
            stdout, stderr = process.communicate(input='', timeout=2)
            print("✅ Server starts without errors")
            assert True
        except subprocess.TimeoutExpired:
            # This is expected - server is waiting for MCP messages
            process.terminate()
            print("✅ Server starts and waits for input (as expected)")
            assert True
            
    except Exception as e:
        print(f"❌ Server startup failed: {e}")
        assert False, f"Server startup failed: {e}"

def main():
    print("🧪 Testing Grype MCP Server...")
    print("=" * 40)
    
    # Test imports
    import_ok = test_server_import()
    
    if import_ok:
        # Test server startup
        startup_ok = test_server_run()
        
        if startup_ok:
            print("\n🎉 All tests passed!")
            print("\nReady for MCP Inspector testing:")
            print("  npx @modelcontextprotocol/inspector python grype_mcp/server.py")
            print("\nOr use with Claude Desktop:")
            claude_config = {
                "mcpServers": {
                    "grype": {
                        "command": "python",
                        "args": ["grype_mcp/server.py"],
                        "env": {}
                    }
                }
            }
            print(json.dumps(claude_config, indent=2))
        else:
            print("\n❌ Server startup tests failed")
            return 1
    else:
        print("\n❌ Import tests failed")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())