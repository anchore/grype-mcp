#!/usr/bin/env python3
"""
Official Anchore Grype MCP Server

A Model Context Protocol server that provides vulnerability scanning capabilities
using Grype as the backend scanner.

This is the official Anchore implementation for integrating Grype with AI assistants.
"""

import asyncio
import json
import subprocess
import sys
import shutil
import os
from typing import Any, Dict, List, Optional
from pathlib import Path

import click
from mcp.server.fastmcp import FastMCP

# Initialize the MCP server using FastMCP
mcp = FastMCP("grype-mcp-server")

class GrypeError(Exception):
    """Custom exception for Grype-related errors"""
    pass

class GrypeInstaller:
    """Handles Grype installation and updates"""
    
    @staticmethod
    async def find_grype() -> Optional[str]:
        """Find grype binary in PATH or current directory"""
        # First check PATH
        grype_path = shutil.which("grype")
        if grype_path:
            return grype_path
            
        # If not in PATH, check for local binary in current directory
        local_grype = Path("./grype")
        if local_grype.exists() and local_grype.is_file():
            # Make sure it's executable
            if os.access(local_grype, os.X_OK):
                return str(local_grype.absolute())
        
        return None
    
    @staticmethod
    async def get_grype_binary_path() -> str:
        """Get the path to the grype binary, preferring local over PATH"""
        grype_path = await GrypeInstaller.find_grype()
        if grype_path:
            return grype_path
        else:
            # Fallback to just "grype" and let the system handle the error
            return "grype"
    
    @staticmethod
    async def install_grype() -> bool:
        """Install or update grype using the official installer script"""
        try:
            # Use the official Anchore installer
            install_cmd = [
                "curl", "-sSfL", 
                "https://get.anchore.io/grype"
            ]
            
            # Pipe to shell for execution
            curl_process = await asyncio.create_subprocess_exec(
                *install_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            script_content, curl_stderr = await curl_process.communicate()
            
            if curl_process.returncode != 0:
                raise GrypeError(f"Failed to download installer: {curl_stderr.decode()}")
            
            # Execute the installer script
            install_process = await asyncio.create_subprocess_exec(
                "sh", "-s", "--", "-b", "./",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await install_process.communicate(script_content)
            
            if install_process.returncode == 0:
                return True
            else:
                raise GrypeError(f"Installation failed: {stderr.decode()}")
                
        except Exception as e:
            raise GrypeError(f"Failed to install grype: {e}")

class GrypeRunner:
    """Handles running Grype CLI commands and parsing results"""
    
    @staticmethod
    async def run_grype_command(args: List[str], timeout: int = 120, json_output: bool = True) -> Any:
        """
        Run a grype command and return results
        
        Args:
            args: Command line arguments for grype
            timeout: Command timeout in seconds
            json_output: Whether to expect JSON output (adds -o json if True)
            
        Returns:
            Parsed JSON output from grype (if json_output=True) or raw text output
            
        Raises:
            GrypeError: If grype command fails or returns invalid JSON
        """
        try:
            # Ensure JSON output format for scanning commands
            if json_output and "-o" not in args and "--output" not in args:
                args.extend(["-o", "json"])
            
            # Get the correct grype binary path
            grype_binary = await GrypeInstaller.get_grype_binary_path()
            cmd = [grype_binary] + args
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                result.communicate(), 
                timeout=timeout
            )
            
            if result.returncode != 0:
                error_msg = stderr.decode('utf-8') if stderr else "Unknown grype error"
                raise GrypeError(f"Grype command failed: {error_msg}")
            
            # Parse output based on expected format
            if json_output:
                try:
                    return json.loads(stdout.decode('utf-8'))
                except json.JSONDecodeError as e:
                    raise GrypeError(f"Failed to parse grype JSON output: {e}")
            else:
                # Return raw text output for non-JSON commands
                return stdout.decode('utf-8')
                
        except asyncio.TimeoutError:
            raise GrypeError(f"Grype command timed out after {timeout} seconds")
        except Exception as e:
            raise GrypeError(f"Failed to run grype command: {e}")
    
    @staticmethod
    def format_vulnerability_summary(grype_output: Dict[str, Any]) -> str:
        """Format grype output into a human-readable summary"""
        if not grype_output.get("matches"):
            return "No vulnerabilities found"
        
        matches = grype_output["matches"]
        total_vulns = len(matches)
        
        # Count by severity
        severity_counts = {}
        for match in matches:
            severity = match.get("vulnerability", {}).get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Build summary
        summary_parts = [f"Found {total_vulns} vulnerability(ies)"]
        if severity_counts:
            severity_list = [f"{count} {severity}" for severity, count in severity_counts.items()]
            summary_parts.append(f"Severity breakdown: {', '.join(severity_list)}")
        
        return ". ".join(summary_parts)

# Tool implementations using FastMCP decorators

@mcp.tool()
async def find_grype() -> str:
    """Find the grype binary and check if it's installed.
    
    Returns information about grype installation status.
    """
    try:
        grype_path = await GrypeInstaller.find_grype()
        
        if grype_path:
            # Determine if it's local or in PATH
            is_local = grype_path.startswith(os.getcwd()) or grype_path.startswith("./")
            location_desc = "locally" if is_local else "in PATH"
            
            # Get version info
            try:
                version_output = await GrypeRunner.run_grype_command(["version"], json_output=False, timeout=30)
                version_lines = version_output.split('\n')
                version_info = {}
                for line in version_lines:
                    if 'Version:' in line:
                        version_info["version"] = line.split('Version:')[-1].strip()
                        break
                
                response = {
                    "success": True,
                    "tool": "find_grype",
                    "results": {
                        "found": True,
                        "path": grype_path,
                        "is_local": is_local,
                        "version": version_info.get("version", "Unknown"),
                        "summary": f"Grype found {location_desc} at {grype_path}, version {version_info.get('version', 'Unknown')}"
                    }
                }
            except:
                response = {
                    "success": True,
                    "tool": "find_grype", 
                    "results": {
                        "found": True,
                        "path": grype_path,
                        "is_local": is_local,
                        "version": "Unknown",
                        "summary": f"Grype found {location_desc} at {grype_path} but version check failed"
                    }
                }
        else:
            response = {
                "success": True,
                "tool": "find_grype",
                "results": {
                    "found": False,
                    "path": None,
                    "is_local": False,
                    "version": None,
                    "summary": "Grype not found in PATH or locally. Use update_grype to install."
                }
            }
        
        return json.dumps(response, indent=2)
        
    except Exception as e:
        error_response = {
            "success": False,
            "tool": "find_grype",
            "error": str(e),
            "message": f"Error checking grype installation: {str(e)}"
        }
        return json.dumps(error_response, indent=2)

@mcp.tool()
async def update_grype() -> str:
    """Install or update the grype binary to the latest version.
    
    Downloads and installs grype using the official Anchore installer.
    """
    try:
        # Check current installation
        current_path = await GrypeInstaller.find_grype()
        
        response_data = {
            "success": True,
            "tool": "update_grype",
            "results": {
                "previous_installation": current_path,
                "action_performed": "install" if not current_path else "update"
            }
        }
        
        # Install/update grype
        install_success = await GrypeInstaller.install_grype()
        
        if install_success:
            # Verify installation
            new_path = await GrypeInstaller.find_grype()
            if new_path:
                is_local = new_path.startswith(os.getcwd()) or new_path.startswith("./")
                location_desc = "locally" if is_local else "in PATH"
                
                try:
                    version_output = await GrypeRunner.run_grype_command(["version"], json_output=False, timeout=30)
                    version_lines = version_output.split('\n')
                    for line in version_lines:
                        if 'Version:' in line:
                            new_version = line.split('Version:')[-1].strip()
                            break
                    else:
                        new_version = "Unknown"
                    
                    response_data["results"].update({
                        "new_path": new_path,
                        "new_version": new_version,
                        "is_local": is_local,
                        "summary": f"Successfully {'installed' if not current_path else 'updated'} grype {location_desc} to version {new_version}"
                    })
                except:
                    response_data["results"].update({
                        "new_path": new_path,
                        "new_version": "Unknown",
                        "is_local": is_local,
                        "summary": f"Successfully {'installed' if not current_path else 'updated'} grype {location_desc} (version check failed)"
                    })
            else:
                raise GrypeError("Installation succeeded but grype not found in PATH or locally")
        else:
            raise GrypeError("Installation failed")
        
        return json.dumps(response_data, indent=2)
        
    except GrypeError as e:
        error_response = {
            "success": False,
            "tool": "update_grype",
            "error": str(e),
            "message": f"Failed to install/update grype: {str(e)}"
        }
        return json.dumps(error_response, indent=2)
        
    except Exception as e:
        error_response = {
            "success": False,
            "tool": "update_grype",
            "error": str(e),
            "message": f"Unexpected error during grype installation: {str(e)}"
        }
        return json.dumps(error_response, indent=2)

@mcp.tool()
async def scan_dir(path: str, include_dev: bool = False) -> str:
    """Scan a directory for vulnerabilities using Grype.
    
    Args:
        path: Path to the directory to scan
        include_dev: Include development dependencies
    """
    try:
        # Validate path exists
        from pathlib import Path as PathLib
        dir_path = PathLib(path)
        if not dir_path.exists():
            raise GrypeError(f"Directory does not exist: {path}")
        if not dir_path.is_dir():
            raise GrypeError(f"Path is not a directory: {path}")
        
        # Build grype command
        grype_args = [f"dir:{path}", "-o", "json"]
        
        # Add scope for dev dependencies if requested
        if not include_dev:
            grype_args.extend(["--scope", "Squashed"])  # Exclude dev dependencies
        
        # Run grype command
        grype_output = await GrypeRunner.run_grype_command(grype_args)
        
        # Parse vulnerabilities
        vulnerabilities = []
        vulnerability_count = 0
        packages_scanned = set()
        
        if "matches" in grype_output and grype_output["matches"]:
            vulnerability_count = len(grype_output["matches"])
            
            for match in grype_output["matches"]:
                vuln_info = match.get("vulnerability", {})
                artifact = match.get("artifact", {})
                
                # Track unique packages
                pkg_name = artifact.get("name", "Unknown")
                pkg_version = artifact.get("version", "Unknown")
                packages_scanned.add(f"{pkg_name}@{pkg_version}")
                
                vuln = {
                    "id": vuln_info.get("id", "Unknown"),
                    "severity": vuln_info.get("severity", "Unknown"),
                    "description": vuln_info.get("description", "")[:200] + "..." if len(vuln_info.get("description", "")) > 200 else vuln_info.get("description", ""),
                    "fixed_versions": vuln_info.get("fix", {}).get("versions", []),
                    "package_name": pkg_name,
                    "package_version": pkg_version,
                    "package_type": artifact.get("type", "Unknown"),
                    "package_location": artifact.get("locations", [{}])[0].get("path", "Unknown")
                }
                
                # Add CVSS/risk info if available
                if "cvss" in vuln_info:
                    cvss_list = vuln_info["cvss"]
                    if cvss_list and len(cvss_list) > 0:
                        cvss = cvss_list[0].get("metrics", {}).get("baseScore")
                        if cvss:
                            vuln["cvss_score"] = cvss
                
                vulnerabilities.append(vuln)
        
        # Count packages from source if available
        total_packages = len(packages_scanned)
        
        # Generate summary
        summary = GrypeRunner.format_vulnerability_summary(grype_output)
        if total_packages > 0:
            summary += f" across {total_packages} packages"
        
        response = {
            "success": True,
            "tool": "scan_dir",
            "input": {"path": path, "include_dev": include_dev},
            "results": {
                "path_scanned": str(dir_path.absolute()),
                "vulnerability_count": vulnerability_count,
                "packages_scanned": total_packages,
                "vulnerabilities": vulnerabilities,
                "summary": summary,
                "scan_timestamp": grype_output.get("descriptor", {}).get("timestamp", "Unknown")
            }
        }
        
        return json.dumps(response, indent=2)
        
    except GrypeError as e:
        error_response = {
            "success": False,
            "tool": "scan_dir",
            "input": {"path": path, "include_dev": include_dev},
            "error": str(e),
            "message": f"Grype scanning failed: {str(e)}"
        }
        return json.dumps(error_response, indent=2)
        
    except Exception as e:
        error_response = {
            "success": False,
            "tool": "scan_dir",
            "input": {"path": path, "include_dev": include_dev},
            "error": str(e),
            "message": f"Unexpected error during scan: {str(e)}"
        }
        return json.dumps(error_response, indent=2)

@mcp.tool()
async def scan_purl(package_url: str) -> str:
    """Scan a specific package using PURL (Package URL) format.
    
    Args:
        package_url: Package URL in PURL format (e.g., pkg:npm/lodash@4.17.20)
    """
    try:
        # Run grype command with JSON output
        grype_output = await GrypeRunner.run_grype_command([package_url, "-o", "json"])
        
        # Parse vulnerabilities from grype output
        vulnerabilities = []
        vulnerability_count = 0
        
        if "matches" in grype_output and grype_output["matches"]:
            vulnerability_count = len(grype_output["matches"])
            
            for match in grype_output["matches"]:
                vuln_info = match.get("vulnerability", {})
                artifact = match.get("artifact", {})
                
                vuln = {
                    "id": vuln_info.get("id", "Unknown"),
                    "severity": vuln_info.get("severity", "Unknown"),
                    "description": vuln_info.get("description", "")[:200] + "..." if len(vuln_info.get("description", "")) > 200 else vuln_info.get("description", ""),
                    "fixed_versions": vuln_info.get("fix", {}).get("versions", []),
                    "package_name": artifact.get("name", "Unknown"),
                    "package_version": artifact.get("version", "Unknown"),
                    "package_type": artifact.get("type", "Unknown")
                }
                
                # Add CVSS/risk info if available
                if "cvss" in vuln_info:
                    cvss_list = vuln_info["cvss"]
                    if cvss_list and len(cvss_list) > 0:
                        cvss = cvss_list[0].get("metrics", {}).get("baseScore")
                        if cvss:
                            vuln["cvss_score"] = cvss
                
                vulnerabilities.append(vuln)
        
        # Generate summary
        summary = GrypeRunner.format_vulnerability_summary(grype_output)
        
        response = {
            "success": True,
            "tool": "scan_purl",
            "input": {"package_url": package_url},
            "results": {
                "package_url": package_url,
                "vulnerability_count": vulnerability_count,
                "vulnerabilities": vulnerabilities,
                "summary": summary,
                "scan_timestamp": grype_output.get("descriptor", {}).get("timestamp", "Unknown")
            }
        }
        
        return json.dumps(response, indent=2)
        
    except GrypeError as e:
        error_response = {
            "success": False,
            "tool": "scan_purl",
            "input": {"package_url": package_url},
            "error": str(e),
            "message": f"Grype scanning failed: {str(e)}"
        }
        return json.dumps(error_response, indent=2)
        
    except Exception as e:
        error_response = {
            "success": False,
            "tool": "scan_purl",
            "input": {"package_url": package_url},
            "error": str(e),
            "message": f"Unexpected error during scan: {str(e)}"
        }
        return json.dumps(error_response, indent=2)

@mcp.tool()
async def scan_image(image: str) -> str:
    """Scan a container image for vulnerabilities.
    
    Args:
        image: Container image name/tag (e.g., nginx:latest, ubuntu:20.04)
    """
    try:
        # Validate image format (basic check)
        if not image or len(image.strip()) == 0:
            raise GrypeError("Image name cannot be empty")
        
        image = image.strip()
        
        # Build grype command for container image scanning
        grype_args = [image, "-o", "json"]
        
        # Run grype scan on the container image (longer timeout for image pulls)
        grype_output = await GrypeRunner.run_grype_command(grype_args, timeout=300)
        
        # Parse vulnerabilities
        vulnerabilities = []
        vulnerability_count = 0
        packages_scanned = set()
        image_info = {}
        
        # Extract image source information if available
        if "source" in grype_output:
            source = grype_output["source"]
            image_info = {
                "image_id": source.get("imageID", "Unknown"),
                "image_size": source.get("imageSize", "Unknown"),
                "layers": len(source.get("manifest", {}).get("layers", [])),
                "os": source.get("metadata", {}).get("os", "Unknown"),
                "architecture": source.get("metadata", {}).get("architecture", "Unknown")
            }
        
        if "matches" in grype_output and grype_output["matches"]:
            vulnerability_count = len(grype_output["matches"])
            
            for match in grype_output["matches"]:
                vuln_info = match.get("vulnerability", {})
                artifact = match.get("artifact", {})
                
                # Track unique packages in the image
                pkg_name = artifact.get("name", "Unknown")
                pkg_version = artifact.get("version", "Unknown")
                pkg_type = artifact.get("type", "Unknown")
                packages_scanned.add(f"{pkg_name}@{pkg_version} ({pkg_type})")
                
                vuln = {
                    "id": vuln_info.get("id", "Unknown"),
                    "severity": vuln_info.get("severity", "Unknown"),
                    "description": vuln_info.get("description", "")[:200] + "..." if len(vuln_info.get("description", "")) > 200 else vuln_info.get("description", ""),
                    "fixed_versions": vuln_info.get("fix", {}).get("versions", []),
                    "package_name": pkg_name,
                    "package_version": pkg_version,
                    "package_type": pkg_type,
                    "package_location": artifact.get("locations", [{}])[0].get("path", "Unknown"),
                    "layer_info": artifact.get("metadata", {}).get("layerID", "Unknown")
                }
                
                # Add CVSS/risk info if available
                if "cvss" in vuln_info:
                    cvss_list = vuln_info["cvss"]
                    if cvss_list and len(cvss_list) > 0:
                        cvss = cvss_list[0].get("metrics", {}).get("baseScore")
                        if cvss:
                            vuln["cvss_score"] = cvss
                
                vulnerabilities.append(vuln)
        
        # Generate summary
        summary = GrypeRunner.format_vulnerability_summary(grype_output)
        total_packages = len(packages_scanned)
        if total_packages > 0:
            summary += f" across {total_packages} packages in container image"
        
        response = {
            "success": True,
            "tool": "scan_image",
            "input": {"image": image},
            "results": {
                "image": image,
                "image_info": image_info,
                "vulnerability_count": vulnerability_count,
                "packages_scanned": total_packages,
                "vulnerabilities": vulnerabilities,
                "summary": summary,
                "scan_timestamp": grype_output.get("descriptor", {}).get("timestamp", "Unknown")
            }
        }
        
        return json.dumps(response, indent=2)
        
    except GrypeError as e:
        # Handle common Docker/image-related errors
        error_msg = str(e)
        if "unable to pull image" in error_msg.lower():
            helpful_msg = f"Unable to pull image '{image}'. Check that the image exists and is accessible. For private images, ensure Docker is logged in."
        elif "docker" in error_msg.lower() and "not found" in error_msg.lower():
            helpful_msg = f"Docker not available. Grype needs Docker to scan container images."
        else:
            helpful_msg = f"Container scanning failed: {error_msg}"
            
        error_response = {
            "success": False,
            "tool": "scan_image",
            "input": {"image": image},
            "error": str(e),
            "message": helpful_msg
        }
        return json.dumps(error_response, indent=2)
        
    except Exception as e:
        error_response = {
            "success": False,
            "tool": "scan_image",
            "input": {"image": image},
            "error": str(e),
            "message": f"Unexpected error during container scan: {str(e)}"
        }
        return json.dumps(error_response, indent=2)

@mcp.tool()
async def search_vulns(query: str, search_type: str = "vuln") -> str:
    """Search the Grype database for vulnerability information.
    
    Args:
        query: Search query (CVE ID, package name, etc.)
        search_type: Type of search: vuln, package, or cpe
    """
    try:
        # Validate search type
        valid_types = ["vuln", "package", "cpe"]
        if search_type not in valid_types:
            raise GrypeError(f"Invalid search type '{search_type}'. Must be one of: {', '.join(valid_types)}")
        
        # Build grype db search command
        grype_args = ["db", "search", search_type, query, "-o", "json"]
        
        # Run the search command
        grype_output = await GrypeRunner.run_grype_command(grype_args)
        
        # Parse the search results
        matches = []
        total_matches = 0
        
        if isinstance(grype_output, list):
            # grype db search returns an array of results
            total_matches = len(grype_output)
            
            for item in grype_output:
                if search_type == "vuln":
                    # Vulnerability search result
                    match = {
                        "id": item.get("id", "Unknown"),
                        "severity": item.get("severity", "Unknown"),
                        "description": item.get("description", "")[:300] + "..." if len(item.get("description", "")) > 300 else item.get("description", ""),
                        "published_date": item.get("published_date", "Unknown"),
                        "modified_date": item.get("modified_date", "Unknown"),
                        "provider": item.get("provider", "Unknown")
                    }
                    
                    # Add CVSS if available
                    if "severities" in item and item["severities"]:
                        severities = item["severities"]
                        for sev in severities:
                            if "score" in sev:
                                match["cvss_score"] = sev["score"]
                                break
                    
                    # Add references if available
                    if "refs" in item and item["refs"]:
                        match["references"] = item["refs"][:3]  # First 3 references
                    
                elif search_type == "package":
                    # Package search result
                    match = {
                        "package_name": item.get("package", {}).get("name", "Unknown"),
                        "package_type": item.get("package", {}).get("type", "Unknown"),
                        "vulnerability_id": item.get("vulnerability", {}).get("id", "Unknown"),
                        "severity": item.get("vulnerability", {}).get("severity", "Unknown"),
                        "constraint": item.get("constraint", "Unknown")
                    }
                    
                elif search_type == "cpe":
                    # CPE search result
                    match = {
                        "cpe": item.get("cpe", "Unknown"),
                        "vulnerability_id": item.get("vulnerability", {}).get("id", "Unknown"),
                        "severity": item.get("vulnerability", {}).get("severity", "Unknown")
                    }
                
                matches.append(match)
        
        elif isinstance(grype_output, dict) and "error" in str(grype_output).lower():
            # Handle case where search returns error info
            error_msg = str(grype_output)
            if "no matches found" in error_msg.lower():
                total_matches = 0
                matches = []
            else:
                raise GrypeError(f"Database search error: {error_msg}")
        
        # Generate summary
        if total_matches == 0:
            summary = f"No matches found for '{query}' in {search_type} database"
        else:
            summary = f"Found {total_matches} matches for '{query}' in {search_type} database"
            
            # Add breakdown by severity for vulnerability searches
            if search_type == "vuln" and matches:
                severity_counts = {}
                for match in matches:
                    severity = match.get("severity", "Unknown")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                if severity_counts:
                    severity_breakdown = [f"{count} {sev.lower()}" for sev, count in severity_counts.items()]
                    summary += f" ({', '.join(severity_breakdown)})"
        
        response = {
            "success": True,
            "tool": "search_vulns",
            "input": {"query": query, "search_type": search_type},
            "results": {
                "query": query,
                "search_type": search_type,
                "total_matches": total_matches,
                "matches": matches,
                "summary": summary
            }
        }
        
        return json.dumps(response, indent=2)
        
    except GrypeError as e:
        error_response = {
            "success": False,
            "tool": "search_vulns",
            "input": {"query": query, "search_type": search_type},
            "error": str(e),
            "message": f"Database search failed: {str(e)}"
        }
        return json.dumps(error_response, indent=2)
        
    except Exception as e:
        error_response = {
            "success": False,
            "tool": "search_vulns",
            "input": {"query": query, "search_type": search_type},
            "error": str(e),
            "message": f"Unexpected error during search: {str(e)}"
        }
        return json.dumps(error_response, indent=2)

@mcp.tool()
async def get_vuln_details(cve_id: str) -> str:
    """Get detailed information about a specific vulnerability.
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2021-44228)
    """
    try:
        # Validate CVE format (basic check)
        if not cve_id.upper().startswith("CVE-"):
            # Try to be helpful - maybe they just gave the number
            if cve_id.replace("-", "").isdigit():
                cve_id = f"CVE-{cve_id}"
            else:
                raise GrypeError(f"Invalid CVE format: {cve_id}. Expected format: CVE-YYYY-NNNN")
        
        # Use search_vulnerabilities to get the details
        grype_args = ["db", "search", "vuln", cve_id, "-o", "json"]
        grype_output = await GrypeRunner.run_grype_command(grype_args)
        
        # Parse the results
        vulnerability_details = None
        
        if isinstance(grype_output, list) and len(grype_output) > 0:
            # Found the vulnerability
            vuln_data = grype_output[0]  # Take the first (should be exact match)
            
            vulnerability_details = {
                "id": vuln_data.get("id", cve_id),
                "severity": vuln_data.get("severity", "Unknown"),
                "description": vuln_data.get("description", "No description available"),
                "published_date": vuln_data.get("published_date", "Unknown"),
                "modified_date": vuln_data.get("modified_date", "Unknown"),
                "provider": vuln_data.get("provider", "Unknown"),
                "status": vuln_data.get("status", "Unknown")
            }
            
            # Add CVSS scores if available
            cvss_scores = []
            if "severities" in vuln_data and vuln_data["severities"]:
                for severity in vuln_data["severities"]:
                    if "score" in severity:
                        cvss_info = {
                            "score": severity["score"],
                            "vector": severity.get("vector", "Unknown"),
                            "source": severity.get("source", "Unknown")
                        }
                        cvss_scores.append(cvss_info)
            
            if cvss_scores:
                vulnerability_details["cvss_scores"] = cvss_scores
                # Set primary CVSS score
                vulnerability_details["primary_cvss_score"] = cvss_scores[0]["score"]
            
            # Add references if available
            if "refs" in vuln_data and vuln_data["refs"]:
                vulnerability_details["references"] = vuln_data["refs"]
            
            # Add assigners if available
            if "assigner" in vuln_data:
                vulnerability_details["assigner"] = vuln_data["assigner"]
            
            # Check for known exploited status (CISA KEV)
            if "known_exploited" in vuln_data:
                vulnerability_details["known_exploited"] = vuln_data["known_exploited"]
                if vuln_data["known_exploited"]:
                    vulnerability_details["exploit_info"] = {
                        "cisa_kev": True,
                        "due_date": vuln_data.get("due_date", "Unknown"),
                        "required_action": vuln_data.get("required_action", "Unknown")
                    }
            
            summary = f"CVE details retrieved: {vulnerability_details['severity']} severity"
            if "primary_cvss_score" in vulnerability_details:
                summary += f" (CVSS {vulnerability_details['primary_cvss_score']})"
            
        else:
            # Vulnerability not found
            vulnerability_details = {
                "id": cve_id,
                "found": False,
                "message": "Vulnerability not found in Grype database"
            }
            summary = f"CVE {cve_id} not found in database"
        
        response = {
            "success": True,
            "tool": "get_vuln_details",
            "input": {"cve_id": cve_id},
            "results": {
                "cve_id": cve_id,
                "details": vulnerability_details,
                "summary": summary
            }
        }
        
        return json.dumps(response, indent=2)
        
    except GrypeError as e:
        error_response = {
            "success": False,
            "tool": "get_vuln_details",
            "input": {"cve_id": cve_id},
            "error": str(e),
            "message": f"Failed to get vulnerability details: {str(e)}"
        }
        return json.dumps(error_response, indent=2)
        
    except Exception as e:
        error_response = {
            "success": False,
            "tool": "get_vuln_details",
            "input": {"cve_id": cve_id},
            "error": str(e),
            "message": f"Unexpected error getting vulnerability details: {str(e)}"
        }
        return json.dumps(error_response, indent=2)

@mcp.tool()
async def get_db_info() -> str:
    """Get information about the Grype vulnerability database."""
    try:
        # Get grype version info which includes database info
        version_output = await GrypeRunner.run_grype_command(["version"], json_output=False)
        
        # Parse version information
        db_info = {
            "grype_version": "Unknown",
            "syft_version": "Unknown", 
            "go_version": "Unknown",
            "supported_db_schema": "Unknown",
            "build_date": "Unknown"
        }
        
        # grype version returns text, parse it directly
        version_text = version_output if isinstance(version_output, str) else str(version_output)
        
        # Try to extract version info from text output
        lines = version_text.split('\n')
        for line in lines:
            if 'Version:' in line:
                db_info["grype_version"] = line.split('Version:')[-1].strip()
            elif 'Syft Version:' in line:
                db_info["syft_version"] = line.split('Syft Version:')[-1].strip()
            elif 'GoVersion:' in line:
                db_info["go_version"] = line.split('GoVersion:')[-1].strip()
            elif 'BuildDate:' in line:
                db_info["build_date"] = line.split('BuildDate:')[-1].strip()
            elif 'Supported DB Schema:' in line:
                db_info["supported_db_schema"] = line.split('Supported DB Schema:')[-1].strip()
        
        # Try a simple scan to verify database is working
        try:
            test_result = await GrypeRunner.run_grype_command(["pkg:npm/test@1.0.0", "-o", "json"], timeout=30)
            db_working = True
            db_status = "operational"
        except:
            db_working = False
            db_status = "error or not downloaded"
        
        summary = f"Grype {db_info['grype_version']} - Database {db_status}"
        
        response = {
            "success": True,
            "tool": "get_db_info",
            "input": {},
            "results": {
                "grype_version": db_info["grype_version"],
                "syft_version": db_info["syft_version"],
                "go_version": db_info["go_version"],
                "build_date": db_info["build_date"],
                "supported_db_schema": db_info["supported_db_schema"],
                "database_status": db_status,
                "database_working": db_working,
                "summary": summary
            }
        }
        
        return json.dumps(response, indent=2)
        
    except GrypeError as e:
        error_response = {
            "success": False,
            "tool": "get_db_info",
            "input": {},
            "error": str(e),
            "message": f"Failed to get database info: {str(e)}"
        }
        return json.dumps(error_response, indent=2)
        
    except Exception as e:
        error_response = {
            "success": False,
            "tool": "get_db_info",
            "input": {},
            "error": str(e),
            "message": f"Unexpected error getting database info: {str(e)}"
        }
        return json.dumps(error_response, indent=2)

@mcp.tool()
async def update_db(force: bool = False) -> str:
    """Update the Grype vulnerability database.
    
    Args:
        force: Force update even if database is recent
    """
    try:
        # Build the grype db update command
        grype_args = ["db", "update"]
        
        # Add force flag if requested
        if force:
            grype_args.append("-f")  # or --force, depending on grype version
        
        # Record start time for duration calculation
        import time
        start_time = time.time()
        
        # Run the database update command (no JSON output expected)
        # This can take a while (downloading ~66MB database)
        grype_output = await GrypeRunner.run_grype_command(grype_args, timeout=600, json_output=False)
        
        end_time = time.time()
        duration = round(end_time - start_time, 1)
        
        # Parse the update results
        update_info = {
            "duration_seconds": duration,
            "force_update": force
        }
        
        # grype db update returns text output
        output_text = grype_output if isinstance(grype_output, str) else str(grype_output)
        
        # Try to extract useful information from the output
        if "already up-to-date" in output_text.lower():
            update_performed = False
            result_message = "Database was already up-to-date"
        elif "updated" in output_text.lower() or "download" in output_text.lower():
            update_performed = True
            result_message = "Database updated successfully"
        elif "no update available" in output_text.lower():
            update_performed = False
            result_message = "No database update available"
        else:
            # Assume success if no error was thrown
            update_performed = True
            result_message = "Database update completed"
        
        # Extract version information if available in output
        update_info["raw_output"] = output_text[:500]  # First 500 chars for debugging
        
        # Try to get current database info to confirm update worked
        try:
            # Quick test scan to verify database is working
            test_result = await GrypeRunner.run_grype_command(["pkg:npm/test@1.0.0", "-o", "json"], timeout=30)
            database_working = True
        except:
            database_working = False
        
        update_info["database_working_after_update"] = database_working
        
        summary = f"{result_message} (took {duration}s)"
        if not database_working:
            summary += " - Warning: Database may not be working properly"
        
        response = {
            "success": True,
            "tool": "update_db",
            "input": {"force": force},
            "results": {
                "update_performed": update_performed,
                "database_working": database_working,
                "update_info": update_info,
                "summary": summary
            }
        }
        
        return json.dumps(response, indent=2)
        
    except GrypeError as e:
        error_msg = str(e)
        
        # Provide helpful error messages for common issues
        if "network" in error_msg.lower() or "connection" in error_msg.lower():
            helpful_msg = f"Database update failed due to network issues: {error_msg}. Check internet connection."
        elif "permission" in error_msg.lower():
            helpful_msg = f"Database update failed due to permission issues: {error_msg}. Try running with appropriate permissions."
        elif "disk" in error_msg.lower() or "space" in error_msg.lower():
            helpful_msg = f"Database update failed due to disk space issues: {error_msg}. Free up some disk space."
        else:
            helpful_msg = f"Database update failed: {error_msg}"
            
        error_response = {
            "success": False,
            "tool": "update_db",
            "input": {"force": force},
            "error": str(e),
            "message": helpful_msg
        }
        return json.dumps(error_response, indent=2)
        
    except Exception as e:
        error_response = {
            "success": False,
            "tool": "update_db",
            "input": {"force": force},
            "error": str(e),
            "message": f"Unexpected error during database update: {str(e)}"
        }
        return json.dumps(error_response, indent=2)

def main():
    """Run the Grype MCP Server"""
    # Use the correct FastMCP API to run the server
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()