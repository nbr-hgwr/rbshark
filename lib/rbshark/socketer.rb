# frozen_string_literal: true

require 'socket'

module Rbshark
  class Socketer
    attr_reader :print_words
    def initialize(options)
      @options = options
      @print_words = []

      @pcap = Rbshark::Dumper.new(@options)
      @pcap.dump_pcap_hdr if @options.key?('write')
    end

    def start
      # Ethernetヘッダ以上のパケットを扱うためのsocketディスクリプタを用意
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
      begin
        while true
          # パケットを受信しないとループが回らないため、終了時間を過ぎてもパケットを受信しないと終了しない
          # 要改善
          if @options.key?('time')
            break if Time.now > end_time
          end

          # パケットの取得部分
          mesg = socket.recvfrom(1024*8)

          # タイムスタンプを取得
          timestamp = Time.now
          first_timestamp = timestamp if packet_count == 1

          # 最初のパケットをキャプチャしてからの経過時間
          time_since = (timestamp - first_timestamp).to_s.split('.')

          # 出力用のpacketデータを生成
          packet_info = Rbshark::PacketInfo.new(packet_count, time_since)

          printer = Rbshark::Printer.new(@options['print'], @options['view'])

          # パケットのデータはrecvfromだと[0]に該当するので分離させる
          frame = mesg[0]

          # pcapファイル出力
          @pcap.dump_packet(@frame, timestamp) if @options.key?('write')

          exec = Rbshark::Executor.new(frame, packet_info, printer)
          exec.exec_ether
          @print_words.push(exec.printer.print_words)

          if @options.key?('count')
            break if end_count <= packet_count
          end
          packet_count += 1
        end
      rescue Interrupt
        puts ""
      end

      puts "#{packet_count} packets captured."
    end
  end
end
