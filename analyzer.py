#!/usr/bin/env python3
import sys
import json
import re

class AdvancedNetworkHeuristicAnalyzer:
    def __init__(self):
        self.suspicious_regex_patterns = [
            re.compile(r"(?i)(SELECT|UNION|INSERT|DROP|ALTER)\s+"),
            re.compile(r"(?i)(cat|ls|id|whoami|sh|bash|etc|passwd)\s+"),
            re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")
        ]
        self.monitored_critical_ports = {21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080}
        self.total_alerts_logged = 0

    def evaluate_payload_safety(self, json_string_packet):
        try:
            packet_data_dictionary = json.loads(json_string_packet)
            target_destination_port = int(packet_data_dictionary.get("dport", 0))
            application_layer_ascii = packet_data_dictionary.get("ascii", "")
            source_address_node = packet_data_dictionary.get("src", "0.0.0.0")
            
            # Port Boundary Structural Scan
            if target_destination_port in self.monitored_critical_ports:
                pass 

            # Deep Structural Pattern Signature Matching Loop
            for pattern_expression in self.suspicious_regex_patterns:
                if pattern_expression.search(application_layer_ascii):
                    self.total_alerts_logged += 1
                    print(f"\033[1;33m[SECURITY HEURISTIC ALERT #{self.total_alerts_logged}]\033[0m "
                          f"Malicious command string match identified from source vector: {source_address_node} "
                          f"| Target Destination Interface: {target_destination_port} | String Context: {application_layer_ascii.strip()}")
                    break

        except (json.JSONDecodeError, ValueError, KeyError):
            return

    def execute_stream_listener(self):
        print("\033[1;36m[INITIALIZED] Python Behavioral Threat Analyzer Loop listening on channel pipe...\033[0m")
        for sequential_line in sys.stdin:
            cleaned_line_buffer = sequential_line.strip()
            if cleaned_line_buffer.startswith("{"):
                self.evaluate_payload_safety(cleaned_line_buffer)

if __name__ == "__main__":
    heuristic_engine_instance = AdvancedNetworkHeuristicAnalyzer()
    heuristic_engine_instance.execute_stream_listener()
