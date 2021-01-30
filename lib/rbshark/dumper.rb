# frozen_string_literal: true

require 'fileutils'

module Rbshark
  class Dumper
    attr_reader :magic_number
    attr_reader :version_major
    attr_reader :version_minor
    attr_reader :thiszone
    attr_reader :sigfigs
    attr_reader :snaplen
    attr_reader :network

    def initialize(options)
      @file_path = options['write']
      @protocol = options['protocol']
      case options['byte_order']
      when 'little'
        @byte_order = 'V*'
      when 'big'
        @byte_order = 'N*'
      else
        $stderr.puts 'Error: byte order is incorrect. -b [litte|big]'
        exit(1)
      end

      set_pcap_hdr
      #create_file(@file_path)
    end

    def create_file(file_path)
      FileUtils.rm(file_path) if File.exist?(file_path)
      FileUtils.touch(file_path)
    end

    def write_file(data)
      pcap_file = File.open(@file_path, 'w')
      pcap_file.puts(data)
      pcap_file.close
    end

    def set_pcap_hdr
      @magic_number = [0xa1b2c3d4].pack(@byte_order)
      # バージョン2.4で固定
      @version_major = [0x0002].pack(@byte_order)
      @version_minor = [0x0004].pack(@byte_order)
      # 0(GMTのオフセット)からホストのタイムゾーンのオフセットを引く
      @thiszone = [(0 - Time.now.utc_offset)].pack(@byte_order)
      # 調査不足のため0で固定
      @sigfigs = [0x00000000].pack(@byte_order)
      # 65535に固定
      @snaplen = [0x0000ffff].pack(@byte_order)
      case @protocol
      when 'all'
        @network = [0x00000065].pack(@byte_order)
      end
      #write_file(pcap_hdr.pack('H*'))
    end

    def packet_convert(frame)
      packet_data = frame.unpack('H*').first.to_i(16)
    end
  end
end