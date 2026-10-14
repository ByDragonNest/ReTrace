"""MCP server wrapping tshark — pcap analysis (protocols, HTTP, DNS, conversations).
Requires tshark on PATH (install Wireshark / tshark).
"""
import os
import subprocess
import sys

# Resolve external tools without depending on the PATH the MCP client happened to inherit.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _toolpath import resolve as _tool

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("tshark")
CAP = 8000


def _run(args, timeout):
    exe = _tool("tshark")
    if not exe:
        return None, "tshark is not installed (install Wireshark/tshark)."
    try:
        p = subprocess.run([exe] + args, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or p.stderr or ""), None
    except subprocess.TimeoutExpired:
        return None, f"tshark: timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return None, f"tshark: error: {e}"


def _cap(s):
    return s[:CAP] + ("\n…(truncated)" if len(s) > CAP else "")


@mcp.tool()
def tshark_protocols(pcap: str, timeout: int = 120) -> str:
    """Protocol hierarchy of a capture file (which protocols and volumes are present)."""
    out, err = _run(["-r", pcap, "-q", "-z", "io,phs"], timeout)
    return err or _cap(out)


@mcp.tool()
def tshark_http(pcap: str, timeout: int = 120) -> str:
    """HTTP requests in a capture: destination IP, host, method, URI, user-agent."""
    out, err = _run(["-r", pcap, "-Y", "http.request", "-T", "fields", "-e", "ip.dst",
                     "-e", "http.host", "-e", "http.request.method", "-e", "http.request.uri",
                     "-e", "http.user_agent", "-E", "separator=|"], timeout)
    return err or _cap(out or "No HTTP requests.")


@mcp.tool()
def tshark_dns(pcap: str, timeout: int = 120) -> str:
    """DNS queries in a capture file."""
    out, err = _run(["-r", pcap, "-Y", "dns.flags.response==0", "-T", "fields",
                     "-e", "dns.qry.name", "-E", "separator=|"], timeout)
    return err or _cap(out or "No DNS queries.")


@mcp.tool()
def tshark_conversations(pcap: str, timeout: int = 120) -> str:
    """TCP conversations (endpoints, packets, bytes) in a capture file."""
    out, err = _run(["-r", pcap, "-q", "-z", "conv,tcp"], timeout)
    return err or _cap(out)


if __name__ == "__main__":
    mcp.run()
