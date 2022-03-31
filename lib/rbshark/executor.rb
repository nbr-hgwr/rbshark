# frozen_string_literal: true

module Rbshark
  class Executor
    def initialize(frame, packet_info, print=true, view=false)
      @frame = frame
      @packet_info = packet_info
      @print = print
      @view = view

      # pcapファイル出力
      @pcap.dump_packet(@frame, timestamp) if @write
      @printer = Rbshark::Printer.new if @print
    end

    def exec_ether
      ether_header = Rbshark::EthernetAnalyzer.new(@frame)
      @packet_info.set_ether(ether_header)
      if @print
        @printer.print_ethernet(ether_header) if @view
      end

      case ether_header.check_protocol_type
      when 'ARP'
        arp_header = Rbshark::ARPAnalyzer.new(@frame, ether_header.return_byte)
        @packet_info.set_arp(arp_header)
        if @print
          @printer.print_arp(arp_header) if @view
          @printer.print_arp_short(@packet_info.packet_info) unless @view
        end
      when 'IP'
        ip_header = Rbshark::IPV4Analyzer.new(@frame, ether_header.return_byte)
        @packet_info.set_ip(ip_header)

        if @print
          @printer.print_ip(ip_header) if @view
        end
        exec_ip(ip_header)
      when 'IPv6'
        ip6_header = IPV6Analyzer.new(@frame, ether_header.return_byte)
        @packet_info.set_ipv6(ip6_header)

        if @print
          @printer.print_ip6(ip6_header) if @view
        end
        exec_ip6(ip6_header)
      end
    end

    def exec_ip(ip_header)
      case ip_header.check_protocol_type
      when 'ICMP'
        icmp = Rbshark::ICMP4Analyzer.new(@frame, ip_header.return_byte)
        @packet_info.set_icmp(icmp)
        if @print
          @printer.print_icmp(icmp) if @view
          @printer.print_icmp_short(@packet_info.packet_info) unless @view
        end
      when 'TCP'
        tcp = Rbshark::TCPAnalyzer.new(@frame, ip_header.return_byte)
        if @print
          @printer.print_tcp(tcp) if @view
          @printer.print_tcp_short(@packet_info.packet_info, tcp) unless @view
        end
      when 'UDP'
        udp = Rbshark::UDPAnalyzer.new(@frame, ip_header.return_byte)
        @printer.print_udp(udp) if @print
      end
    end

    def exec_ip6(ip6_header)
      case ip6_header.check_protocol_type
      when 'ICMP6'
        icmp = Rbshark::ICMP6Analyzer.new(@frame, ip6_header.return_byte)
        @packet_info.set_icmp(icmp)
        if @print
          @printer.print_icmp(icmp) if @view
          @printer.print_icmp6_short(@packet_info.packet_info) unless @view
        end
      when 'TCP'
        tcp = Rbshark::TCPAnalyzer.new(@frame, ip_header.return_byte)
        @printer.print_tcp(tcp) if @print
      when 'UDP'
        udp = Rbshark::UDPAnalyzer.new(@frame, ip_header.return_byte)
        @printer.print_udp(udp) if @print
      end
    end
  end
end
