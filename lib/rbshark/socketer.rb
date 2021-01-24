# frozen_string_literal: true

require 'socket'
require 'rbshark/analyzer'
require 'rbshark/printer'
require 'rbshark/resource/type'

module Rbshark
  class Socketer
    def initialize(interface)
      @interface = interface
    end

    def start
      socket = Socket.open(Socket::AF_PACKET, Socket::SOCK_RAW, Rbshark::ETH_P_ALL)
      ifreq = []
      ifreq.push(@interface)
      ifreq = ifreq.dup.pack('a' + Rbshark::IFREQ_SIZE.to_s)
      socket.ioctl(Rbshark::SIOCGIFINDEX, ifreq)
      if_num = ifreq[Socket::IFNAMSIZ, Rbshark::IFINDEX_SIZE]

      socket.bind(sockaddr_ll(if_num))
      bind(socket)
    end

    def sockaddr_ll(ifnum)
      sll = [Socket::AF_PACKET].pack('s')
      sll << [Rbshark::ETH_P_ALL].pack('s')
      sll << ifnum
      sll << ('\x00' * (Rbshark::SOCKADDR_LL_SIZE - sll.length))
    end

    def bind(socket)
      while true
        mesg = socket.recvfrom(1024*8)
        frame = mesg[0]
        ether_header = Rbshark::EthernetAnalyzer.new(frame)
        printer = Rbshark::Printer.new
        printer.print_ethernet(ether_header)
        case ether_header.check_protocol_type
        when 'ARP'
          arp_header = Rbshark::ARPAnalyzer.new(frame, ether_header.return_byte)
          printer.print_arp(arp_header)
        when 'IP'
          ip_header = Rbshark::IPAnalyzer.new(frame, ether_header.return_byte)
          printer.print_ip(ip_header)
          case ip_header.check_protocol_type
          when 'ICMP'
            icmp = Rbshark::ICMPAnalyzer.new(frame, ip_header.return_byte)
            printer.print_icmp(icmp)
          when 'TCP'
            tcp = Rbshark::TCPAnalyzer.new(frame, ip_header.return_byte)
            printer.print_tcp(tcp)
          when 'UDP'
            udp = Rbshark::UDPAnalyzer.new(frame, ip_header.return_byte)
            printer.print_udp(udp)
          end
          # when 'IPv6'
          # ipv6_header = IPV6Analyzer.new(frame, ether_header.return_byte)
          # print_ip(ipv6_header)
        end
      end
    end
  end
end
