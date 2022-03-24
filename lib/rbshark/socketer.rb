# frozen_string_literal: true

require 'socket'
require 'rbshark/analyzer'
require 'rbshark/printer'
require 'rbshark/executor'
require 'rbshark/resource/type'

module Rbshark
  class Socketer
    def initialize(options, pcap)
      @options = options
      @pcap = pcap
    end

    def start
      socket = Socket.open(Socket::AF_PACKET, Socket::SOCK_RAW, Rbshark::ETH_P_ALL)
      if @options.key?('interface')
        if_num = Rbshark::Interface.new.get_interface(socket, @options['interface'])

        socket.bind(sockaddr_ll(if_num))
      end
      bind(socket)
    end

    def sockaddr_ll(ifnum)
      sll = [Socket::AF_PACKET].pack('s')
      sll << [Rbshark::ETH_P_ALL].pack('s')
      sll << ifnum
      sll << ('\x00' * (Rbshark::SOCKADDR_LL_SIZE - sll.length))
    end

    def bind(socket)
      end_time = Time.now + @options['time'] if @options.key?('time')
      end_count = @options['count'] if @options.key?('count')
      packet_count = 1
      while true
        # パケットを受信しないとループが回らないため、終了時間を過ぎてもパケットを受信しないと終了しない
        # 要改善
        if @options.key?('time')
          break if Time.now > end_time
        end

        # パケットの取得部分
        mesg = socket.recvfrom(1024*8)
        # pcap用のタイムスタンプを取得
        timestamp = Time.now
        # パケットのデータはrecvfromだと[0]に該当するので分離させる
        frame = mesg[0]
        packet_hdr = @pcap.set_packet_hdr(frame, timestamp)
        first_cap_packet = packet_hdr if packet_count == 1
        @pcap.dump_packet(frame, timestamp) if @options['write']
        exec = Rbshark::Executor.new(frame, packet_hdr, first_cap_packet, packet_count, @options['print'], @options['view'], @pcap.byte_order32)
        exec.exec_ether

        packet_count += 1
        if @options.key?('count')
          break if end_count == packet_count
        end
      end

      puts "#{packet_count} packets captured."
    end
  end
end
