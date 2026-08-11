#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <vector>
#include <memory>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

unsigned long long global_packet_index = 0;

std::string compute_safe_json_string(const std::string& input) {
    std::string filtered = "";
    for (char c : input) {
        if (c == '"') filtered += "\\\"";
        else if (c == '\\') filtered += "\\\\";
        else if (c == '\n') filtered += "\\n";
        else if (c == '\r') filtered += "\\r";
        else if (c == '\t') filtered += "\\t";
        else if (c >= 32 && c <= 126) filtered += c;
    }
    return filtered;
}

std::string extract_raw_ascii_layer(const u_char* payload, int size) {
    if (size <= 0) return "";
    std::string text_dump = "";
    for (int i = 0; i < size; ++i) {
        if (payload[i] >= 32 && payload[i] <= 126) {
            text_dump += static_cast<char>(payload[i]);
        } else {
            text_dump += ".";
        }
    }
    return text_dump;
}

void process_captured_hardware_frame(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    global_packet_index++;
    auto current_time_point = std::chrono::system_clock::now();
    long long timestamp_milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(current_time_point.time_since_epoch()).count();

    const int ethernet_header_bytes = 14;
    if (header->len < ethernet_header_bytes) return;

    struct ip* ipv4_header = (struct ip*)(packet + ethernet_header_bytes);
    int ipv4_header_bytes = ipv4_header->ip_hl * 4;
    if (ipv4_header_bytes < 20) return;

    std::string source_address = inet_ntoa(ipv4_header->ip_src);
    std::string destination_address = inet_ntoa(ipv4_header->ip_dst);
    int packet_time_to_live = static_cast<int>(ipv4_header->ip_ttl);
    int IP_protocol_version = static_cast<int>(ipv4_header->ip_v);

    std::string transport_protocol_label = "UNKNOWN";
    u_int16_t source_port_bytes = 0;
    u_int16_t destination_port_bytes = 0;
    std::string control_flags_string = "";
    const u_char* application_payload_pointer = nullptr;
    int application_payload_bytes_count = 0;

    if (ipv4_header->ip_p == IPPROTO_TCP) {
        transport_protocol_label = "TCP";
        struct tcphdr* tcp_layer_header = (struct tcphdr*)(packet + ethernet_header_bytes + ipv4_header_bytes);
        int tcp_layer_header_bytes = tcp_layer_header->th_off * 4;
        source_port_bytes = ntohs(tcp_layer_header->th_sport);
        destination_port_bytes = ntohs(tcp_layer_header->th_dport);

        if (tcp_layer_header->th_flags & TH_SYN) control_flags_string += "SYN ";
        if (tcp_layer_header->th_flags & TH_ACK) control_flags_string += "ACK ";
        if (tcp_layer_header->th_flags & TH_FIN) control_flags_string += "FIN ";
        if (tcp_layer_header->th_flags & TH_RST) control_flags_string += "RST ";
        if (tcp_layer_header->th_flags & TH_PUSH) control_flags_string += "PSH ";

        application_payload_pointer = (packet + ethernet_header_bytes + ipv4_header_bytes + tcp_layer_header_bytes);
        application_payload_bytes_count = ntohs(ipv4_header->ip_len) - (ipv4_header_bytes + tcp_layer_header_bytes);
    } else if (ipv4_header->ip_p == IPPROTO_UDP) {
        transport_protocol_label = "UDP";
        struct udphdr* udp_layer_header = (struct udphdr*)(packet + ethernet_header_bytes + ipv4_header_bytes);
        source_port_bytes = ntohs(udp_layer_header->uh_sport);
        destination_port_bytes = ntohs(udp_layer_header->uh_dport);
        control_flags_string = "NONE";
        application_payload_pointer = (packet + ethernet_header_bytes + ipv4_header_bytes + 8);
        application_payload_bytes_count = ntohs(ipv4_header->ip_len) - (ipv4_header_bytes + 8);
    }

    std::stringstream hexadecimal_stream_builder;
    for (u_int i = 0; i < header->len && i < 128; ++i) {
        hexadecimal_stream_builder << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet[i]);
    }

    std::string ascii_payload_extracted = (application_payload_bytes_count > 0 && application_payload_pointer != nullptr) ? 
        extract_raw_ascii_layer(application_payload_pointer, std::min(application_payload_bytes_count, 128)) : "";

    std::cout << "{\"id\":" << global_packet_index 
              << ",\"time\":" << timestamp_milliseconds 
              << ",\"src\":\"" << source_address 
              << "\",\"dst\":\"" << destination_address 
              << "\",\"ttl\":" << packet_time_to_live 
              << ",\"version\":" << IP_protocol_version 
              << ",\"proto\":\"" << transport_protocol_label 
              << "\",\"sport\":" << source_port_bytes 
              << "\",\"dport\":" << destination_port_bytes 
              << ",\"flags\":\"" << compute_safe_json_string(control_flags_string) 
              << "\",\"hex\":\"" << hexadecimal_stream_builder.str() 
              << "\",\"ascii\":\"" << compute_safe_json_string(ascii_payload_extracted) 
              << "\"}\n" << std::endl;
}

int main(int argc, char* argv[]) {
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_hardware_interfaces, *primary_active_interface;
    std::string execution_target_interface = "";

    if (pcap_findalldevs(&all_hardware_interfaces, pcap_error_buffer) == -1) {
        std::cerr << "{\"error\":\"Failed processing local network interfaces map\"}\n";
        return 1;
    }

    if (argc >= 2) {
        execution_target_interface = argv[1];
    } else {
        primary_active_interface = all_hardware_interfaces;
        if (primary_active_interface == nullptr) {
            std::cerr << "{\"error\":\"Zero running physical network interface paths detected\"}\n";
            pcap_freealldevs(all_hardware_interfaces);
            return 1;
        }
        execution_target_interface = primary_active_interface->name;
    }

    pcap_t* network_pcap_session_handle = pcap_open_live(execution_target_interface.c_str(), 65535, 1, 1000, pcap_error_buffer);
    if (network_pcap_session_handle == nullptr) {
        std::cerr << "{\"error\":\"Root verification failure accessing socket descriptors on interface\"}\n";
        pcap_freealldevs(all_hardware_interfaces);
        return 1;
    }

    struct bpf_program berkeley_filter_compiled_code;
    if (pcap_compile(network_pcap_session_handle, &berkeley_filter_compiled_code, "ip", 0, PCAP_NETMASK_UNKNOWN) != -1) {
        pcap_setfilter(network_pcap_session_handle, &berkeley_filter_compiled_code);
    }

    pcap_loop(network_pcap_session_handle, 0, process_captured_hardware_frame, nullptr);

    pcap_close(network_pcap_session_handle);
    pcap_freealldevs(all_hardware_interfaces);
    return 0;
}
