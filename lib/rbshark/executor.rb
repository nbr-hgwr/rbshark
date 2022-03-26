# frozen_string_literal: true

require 'rbshark/analyzer'
require 'rbshark/printer'
require 'rbshark/resource/packet_info'

module Rbshark
  class Executor
    def initialize(frame, packet_hdr, first_cap_packet, count, print, view, byte_order32)
      @print = print
      @frame = frame
      @packet_hdr = packet_hdr
      @view = view

      cap_time_sec = packet_hdr.packet_hdr[:ts_sec][:value].unpack1(byte_order32).to_i
      cap_time_usec = packet_hdr.packet_hdr[:ts_usec][:value].unpack1(byte_order32).to_i
      first_cap_time_sec = first_cap_packet.packet_hdr[:ts_sec][:value].unpack1(byte_order32).to_i
      first_cap_time_usec = first_cap_packet.packet_hdr[:ts_usec][:value].unpack1(byte_order32).to_i
      time_since = (Time.at(cap_time_sec, cap_time_usec, :usec) - Time.at(first_cap_time_sec.to_i, first_cap_time_usec.to_i, :usec)).to_s.split('.')

      @packet_info = Rbshark::PacketInfo.new(count, time_since)
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
        @printer.print_tcp(tcp) if @print
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
