#!/usr/bin/env python3
import sys
import json
import re
import asyncio
import logging
from concurrent.futures import ProcessPoolExecutor
import hashlib
import ipaddress
from datetime import datetime
import collections
from typing import Dict, List, Set, Optional, Tuple

# Configure low-level terminal telemetry logs
logging.basicConfig(
    level=logging.INFO,
    format="\033[1;35m[TELEMETRY LOG]\033[0m %(asctime)s.%(msecs)03d -> %(message)s",
    datefmt="%H:%M:%S"
)

# Shared memory thresholds for tracking distributed attacks
TRAFFIC_TRACKER: Dict[str, List[float]] = collections.defaultdict(list)
KNOWN_SIGNATURE_ALERTS: int = 0

class AdvancedNetworkHeuristicAnalyzer:
    def __init__(self, max_pps_threshold: int = 200, depth_bytes: int = 256):
        self.max_pps_threshold = max_pps_threshold
        self.depth_bytes = depth_bytes
        
        # Heavy regex matrix targeting credential leaks, SQL injections, and system traversal paths
        self.signature_matrix = {
            "sql_injection": re.compile(r"(?i)(SELECT|UNION|INSERT|DROP|ALTER|UPDATE|DELETE|GRANT)\s+"),
            "system_traversal": re.compile(r"(?i)(cat|ls|id|whoami|sh|bash|etc|passwd|shadow|chmod|wget|curl)\s+"),
            "auth_leak": re.compile(r"(?i)(password|passwd|pwd|secret|pass|token|bearer|apikey|private_key)\s*[:=]\s*"),
            "xss_vector": re.compile(r"(?i)(<script|javascript:|onerror=|onload=)"),
            "shellcode_pattern": re.compile(r"\\x[0-9a-fA-F]{2}")
        }
        
        # Ports that should never send unencrypted text payloads
        self.monitored_critical_ports: Set[int] = {21, 22, 23, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 8080}
        
    def calculate_payload_hashes(self, raw_hex_stream: str) -> Tuple[str, str]:
        """Bypasses standard verification strings to extract raw silicon fingerprint shapes."""
        if not raw_hex_stream:
            return "empty", "empty"
        try:
            binary_payload = bytes.fromhex(raw_hex_stream)
            md5_hash = hashlib.md5(binary_payload).hexdigest()
            sha256_hash = hashlib.sha256(binary_payload).hexdigest()
            return md5_hash, sha256_hash
        except ValueError:
            return "corrupted", "corrupted"

    def analyze_frame_synchronous(self, json_string_packet: str) -> Optional[str]:
        """Heavy numerical and regex signature pattern verification running on dedicated CPU cores."""
        global KNOWN_SIGNATURE_ALERTS
        try:
            packet = json.loads(json_string_packet)
            src_ip = packet.get("src", "0.0.0.0")
            dst_ip = packet.get("dst", "0.0.0.0")
            dport = int(packet.get("dport", 0))
            ascii_payload = packet.get("ascii", "")
            raw_hex = packet.get("hex", "")
            timestamp_ms = float(packet.get("time", 0)) / 1000.0

            # 1. Validate routing layout structures using direct subnet verification
            try:
                ip_object = ipaddress.ip_address(src_ip)
                if ip_object.is_private:
                    routing_class = "INTERNAL_LAN"
                else:
                    routing_class = "EXTERNAL_WAN"
            except ValueError:
                routing_class = "MALFORMED_IP"

            # 2. Fingerprint raw memory layout strings via crypto arrays
            md5_sig, sha256_sig = self.calculate_payload_hashes(raw_hex)

            # 3. Deep heuristic script parsing loops
            alert_context = None
            for alert_type, expression_compiled in self.signature_matrix.items():
                match = expression_compiled.search(ascii_payload)
                if match:
                    KNOWN_SIGNATURE_ALERTS += 1
                    alert_context = (
                        f"\033[1;31m[SIG MATCH: {alert_type.upper()}]\033[0m\n"
                        f"  Endpoint Route : {src_ip} -> {dst_ip}:{dport} [{routing_class}]\n"
                        f"  Crypto Finger  : MD5: {md5_sig} | SHA256: {sha256_sig}\n"
                        f"  Matched String : {match.group(0).strip()}\n"
                        f"  Full Context   : {ascii_payload[:self.depth_bytes].strip()}\n"
                    )
                    break

            # 4. Out-of-bounds explicit alert checks for unencrypted cleartext nodes
            if not alert_context and dport in {21, 23, 80} and len(ascii_payload.strip()) > 0:
                if any(keyword in ascii_payload.lower() for keyword in ["user", "pass", "login", "admin"]):
                    alert_context = (
                        f"\033[1;33m[CLEARTEXT EXPLOIT ALERT]\033[0m Plaintext protocol data active on interface port {dport}\n"
                        f"  Source Node    : {src_ip} -> {dst_ip}\n"
                        f"  Raw String Dump: {ascii_payload.strip()}\n"
                    )

            return alert_context

        except Exception as system_error:
            return f"Parsing anomaly: {str(system_error)}"

class AsyncStreamOrchestrator:
    def __init__(self, analyzer_instance: AdvancedNetworkHeuristicAnalyzer):
        self.analyzer = analyzer_instance
        # Spin up a ProcessPoolExecutor to map CPU-bound regex jobs away from the main thread
        self.cpu_executor = ProcessPoolExecutor(max_workers=4)
        
    async def monitor_traffic_floods(self, json_string_packet: str):
        """Asynchronously tracks sliding-window transaction rates to identify Denial of Service metrics."""
        try:
            packet = json.loads(json_string_packet)
            src_ip = packet.get("src", "0.0.0.0")
            current_time = datetime.utcnow().timestamp()
            
            TRAFFIC_TRACKER[src_ip].append(current_time)
            # Clear historical tracking records older than 1 second
            TRAFFIC_TRACKER[src_ip] = [t for t in TRAFFIC_TRACKER[src_ip] if current_time - t <= 1.0]
            
            if len(TRAFFIC_TRACKER[src_ip]) > self.analyzer.max_pps_threshold:
                logging.warning(
                    f"\033[1;41m[RATE LIMIT VIOLATION]\033[0m High density volume packet burst from: {src_ip} "
                    f"-> Ticks tracked inside 1s window: {len(TRAFFIC_TRACKER[src_ip])} frames"
                )
        except Exception:
            return

    async def ingest_stdin_pipeline(self):
        """Asynchronous system execution thread handling loop transactions on the channel interface pipe."""
        logging.info("Multi-threaded analytical engine initialized. Listening for system inputs...")
        
        # Link an asynchronous reader straight to the terminal standard input descriptor
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            raw_line_bytes = await reader.readline()
            if not raw_line_bytes:
                break
                
            line_decoded = raw_line_bytes.decode('utf-8', errors='ignore').strip()
            if not line_decoded.startswith("{"):
                continue

            # Schedule the asynchronous sliding window rate monitor check
            asyncio.create_task(self.monitor_traffic_floods(line_decoded))

            # Push the heavy signature matching calculation tasks into the Process Pool
            running_loop = asyncio.get_running_loop()
            alert_result = await running_loop.run_in_executor(
                self.cpu_executor, 
                self.analyzer.analyze_frame_synchronous, 
                line_decoded
            )

            if alert_result:
                print(alert_result, flush=True)

        self.cpu_executor.shutdown(wait=True)

if __name__ == "__main__":
    # Initialize the cognitive layers
    heuristic_analyzer = AdvancedNetworkHeuristicAnalyzer(max_pps_threshold=250, depth_bytes=128)
    stream_orchestrator = AsyncStreamOrchestrator(heuristic_analyzer)
    
    # Drop thread loops directly onto the async scheduler execution stack
    try:
        asyncio.run(stream_orchestrator.ingest_stdin_pipeline())
    except KeyboardInterrupt:
        logging.info("Wired operational script context interrupted. Flushing runtime caches.")
        sys.exit(0)

