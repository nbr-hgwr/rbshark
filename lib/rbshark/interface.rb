# frozen_string_literal: true

module Rbshark
  class Interface
    def get_interface(socket, interface)
      # キャプチャを行うネットワークデバイスを取得して返す
      ifreq = []
      ifreq.push(interface)
      ifreq = ifreq.dup.pack('a' + Rbshark::IFREQ_SIZE.to_s)
      socket.ioctl(Rbshark::SIOCGIFINDEX, ifreq)
      if_num = ifreq[Socket::IFNAMSIZ, Rbshark::IFINDEX_SIZE]

      if_num
    end

    def get_interface_list
      Socket.getifaddrs
    end

    def print_interface_list(ifaddrs)
      ifaddrs.each do |ifaddr|
        puts "#{ifaddr.ifindex}: #{ifaddr.name} #{ifaddr.addr.ip_address}" if ifaddr.addr.ip?
      end
    end
  end
end