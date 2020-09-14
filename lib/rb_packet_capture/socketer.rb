require 'socket'
require 'rb_packet_capture/analyzer'
require 'rb_packet_capture/printer'
require 'rb_packet_capture/resouce/type'

module RbPacketCapture
  class Socketer(interface)

    socket = Socket.open(Socket::AF_PACKET, Socket::SOCK_RAW, RbPacketCapture::ETH_P_ALL)
    ifreq = interface
    ifreq = ifreq.dup.pack('a' + RbPacketCapture::IFREQ_SIZE.to_s)
    socket.ioctl(SIOCGIFINDEX, ifreq)
    if_num = ifreq[Socket::IFNAMSIZ, RbPacketCapture::IFINDEX_SIZE]

    def sockaddr_ll(ifnum)
      sll = [Socket::AF_PACKET].pack('s')
      sll << [RbPacketCapture::ETH_P_ALL].pack('s')
      sll << ifnum
      sll << ("\x00" * (RbPacketCapture::SOCKADDR_LL_SIZE - sll.length))
    end

    socket.bind(sockaddr_ll(if_num))

    while (true)
      mesg = socket.recvfrom(1024*8)
      frame = mesg[0]
      ether_header = RbPacketCapture::EthernetAnalyzer.new(frame)
      print_ethernet(ether_header)
      pritnter = RbPacketCapture::Printer.new()
      case ether_header.check_protocol_type
      when "ARP"
        arp_header = RbPacketCapture::ARPAnalyzer.new(frame, ether_header.get_byte)
        pritnter.print_arp(arp_header)
      when "IP"
        ip_header = RbPacketCapture::IPAnalyzer.new(frame, ether_header.get_byte)
        pritnter.print_ip(ip_header)
        case ip_header.check_protocol_type
        when "ICMP"
          icmp = RbPacketCapture::ICMPAnalyzer.new(frame, ip_header.get_byte)
          pritnter.print_icmp(icmp)
        when "TCP"
          tcp = RbPacketCapture::TCPAnalyzer.new(frame, ip_header.get_byte)
          pritnter.print_tcp(tcp)
        when "UDP"
          udp = RbPacketCapture::UDPAnalyzer.new(frame, ip_header.get_byte)
          pritnter.print_udp(udp)
        end
      #when "IPv6"
      #  ipv6_header = IPV6Analyzer.new(frame, ether_header.get_byte)
      #  print_ip(ipv6_header)
      end
    end
  end
end