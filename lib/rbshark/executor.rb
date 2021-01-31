# frozen_string_literal: true

require 'rbshark/analyzer'
require 'rbshark/printer'

module Rbshark
  class Executor
    def initialize(frame, print=nil)
      @print = print
      @frame = frame

      @printer = Rbshark::Printer.new if @print
      exec_ether()
    end

    def exec_ether()
      ether_header = Rbshark::EthernetAnalyzer.new(@frame)
      @printer.print_ethernet(ether_header) if @print

      case ether_header.check_protocol_type
      when 'ARP'
        arp_header = Rbshark::ARPAnalyzer.new(@frame, ether_header.return_byte)
        @printer.print_arp(arp_header) if @print
      when 'IP'
        ip_header = Rbshark::IPAnalyzer.new(@frame, ether_header.return_byte)
        @printer.print_ip(ip_header) if @print
        exec_ip(ip_header)
      # when 'IPv6'
        # ipv6_header = IPV6Analyzer.new(frame, ether_header.return_byte)
        # print_ip(ipv6_header)
      end
    end

    def exec_ip(ip_header)
      case ip_header.check_protocol_type
      when 'ICMP'
        icmp = Rbshark::ICMPAnalyzer.new(@frame, ip_header.return_byte)
        @printer.print_icmp(icmp) if @print
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
