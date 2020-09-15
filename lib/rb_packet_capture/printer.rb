# frozen_string_literal: true

module RbPacketCapture
  class Printer
    def print_ethernet(ether_header)
      puts "Ethernet Header-----------------"
      puts "  dst: #{ether_header.ether_dhost}"
      puts "  src: #{ether_header.ether_shost}"
      puts "  type: #{ether_header.ether_type} (#{ether_header.check_protocol_type})"
    end

    def print_arp(arp_header)
      puts "ARP Header----------------------"
      puts "  [#{arp_header.check_opration}]"
      puts "  sha: #{arp_header.ar_sha}"
      puts "  spa: #{arp_header.ar_sip}"
      puts "  tha: #{arp_header.ar_tha}"
      puts "  tpa: #{arp_header.ar_tip}"
      puts "  arp_hrd: #{arp_header.ar_hrd}"
      puts "  arp_pro: #{arp_header.ar_pro} (#{arp_header.check_protocol_type})"
      puts "  header_len: #{arp_header.ar_hln}"
    end

    def print_ip(ip_header)
      puts "IP Header-----------------------"
      puts "  dst: #{ip_header.ip_dst}"
      puts "  src: #{ip_header.ip_src}"
      puts "  type: #{ip_header.ip_p} (#{ip_header.check_protocol_type})"
      puts "  version: #{ip_header.version}, header_len: #{ip_header.ip_hl}, tos: #{ip_header.ip_tos}"
      puts "  len: #{ip_header.ip_len}, id: #{ip_header.ip_id}, flag_off: #{ip_header.ip_off}"
      puts "  ttl: #{ip_header.ip_ttl}, check: #{ip_header.ip_sum}"
    end

    def print_icmp(icmp)
      puts "ICMP----------------------------"
      puts "  type: #{icmp.icmp_type} (#{icmp.check_type})"
      puts "  code: #{icmp.icmp_code}"
      puts "  check: #{icmp.icmp_checksum}"
    end

    def print_tcp(tcp)
      puts "TCP-----------------------------"
      puts "  src_port: #{tcp.th_sport}"
      puts "  dst_port: #{tcp.th_dport}"
      puts "  sequence: #{tcp.th_seq}, off_set: #{tcp.th_off}"
      puts "  flag: #{tcp.th_flags}, window: #{tcp.th_win}"
      puts "  check: #{tcp.th_sum}, urp: #{tcp.th_urp}"
    end

    def print_udp(udp)
      puts "UDP-----------------------------"
      puts "  src_port: #{udp.uh_sport}"
      puts "  dst_port: #{udp.uh_dport}"
      puts "  len: #{udp.uh_ulen}, check: #{udp.uh_sum}"
    end
  end
end
