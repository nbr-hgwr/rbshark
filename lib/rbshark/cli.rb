# frozen_string_literal: true

require 'thor'

module Rbshark
  # CLIで受けたコマンドに対しての処理を行う
  class CLI < Thor
    class_option :interface, type: :string, aliases: '-i', desc: 'specify interface. ex) -i eth0'
    class_option :time, type: :numeric, aliases: '-t', desc: 'specify end time (s). ex) -t 30'
    class_option :write, type: :string, aliases: '-w', desc: 'specify write path. ex) -w hoge.pcap'
    class_option :byte_order, type: :string, aliases: '-b', default: 'little', desc: 'specify byte order. ex) -b [little|big]. default little'
    class_option :view, type: :boolean, aliases: '-V', default: false, desc: 'view detailed all packets'
    # class_option :protocol, type: :string, aliases: '-p', default: 'all', desc: 'specify protocol type. ex) -p [all|ipv4|ipv6|arp]'

    default_command :analyse

    def self.exit_on_failure?
      true
    end

    desc 'dump <option>', 'dump pcap'
    option :print, type: :boolean, aliases: '-p', default: true, desc: 'use print packet'
    option :count, type: :numeric, aliases: '-c', desc: 'specify packet count'
    option :list_interface, type: :boolean, aliases: '-D', desc: 'show interface list'
    def dump
      if @options.key?('list_interface')
        interfaces = Rbshark::Interface.new
        interfaces.print_interface_list(interfaces.get_interface_list)
        exit(1)
      end
      Rbshark::Socketer.new(@options).start
    end

    desc 'analyze <option>', 'analyse pcap'
    option :read, type: :string, aliases: '-r', desc: 'specify read file. ex) hoge.pcap'
    option :print, type: :boolean, aliases: '-p', default: true, desc: 'use print packet'
    def analyze
      unless options.key?('read')
        warn 'Error: file was not specified. -r <read_filte_path>'
        exit(1)
      end
      pcap = Rbshark::Reader.new(@options['read'])
      count = 1

      # 最初のパケットを取得
      first_packet = pcap.packet_data[0][:hdr]

      # 最初のパケットのtimestampを取得
      first_cap_time_sec = first_packet.packet_hdr[:ts_sec][:value].unpack1(pcap.byte_order32).to_i
      first_cap_time_usec = first_packet.packet_hdr[:ts_usec][:value].unpack1(pcap.byte_order32).to_i

      pcap.packet_data.each do |packet|
        # 最初のパケットとのキャプチャされた時間差を取得
        cap_time_sec = packet[:hdr].packet_hdr[:ts_sec][:value].unpack1(pcap.byte_order32).to_i
        cap_time_usec = packet[:hdr].packet_hdr[:ts_usec][:value].unpack1(pcap.byte_order32).to_i
        time_since = (Time.at(cap_time_sec, cap_time_usec, :usec) - Time.at(first_cap_time_sec.to_i, first_cap_time_usec.to_i, :usec)).to_s.split('.')

        packet_info = Rbshark::PacketInfo.new(count, time_since)

        Rbshark::Executor.new(packet[:data], packet_info, @options['print'], @options['view']).exec_ether
        count += 1
      end
    end
  end
end
