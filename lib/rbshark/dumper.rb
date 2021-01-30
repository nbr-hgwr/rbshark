# frozen_string_literal: true

require 'fileutils'

module Rbshark
  class Dumper
    attr_reader :pcap_hdr

    def initialize(options)
      @file_path = options['write']
      @protocol = options['protocol']
      @offset = 0
      case options['byte_order']
      when 'little'
        @byte_order = 'V*'
      when 'big'
        @byte_order = 'N*'
      else
        warn 'Error: byte order is incorrect. -b [litte|big]'
        exit(1)
      end

      create_file(@file_path)
      set_pcap_hdr
    end

    def create_file(file_path)
      FileUtils.rm(file_path) if File.exist?(file_path)
      #FileUtils.touch(file_path)
    end

    def write_file(value, byte)
      #pcap_file = File.open(@file_path, 'w')
      #pcap_file.puts(data, @offset)
      File.binwrite(@file_path, value, @offset)
      #pcap_file.close
      @offset = @offset + byte
    end

    def set_pcap_hdr
      @pcap_hdr = {
        magic_number: {
          value: [0xa1b2c3d4].pack(@byte_order),
          byte: 4
        },
        # バージョン2.4で固定
        version_major: {
          value: [0x0002].pack(@byte_order),
          byte: 2
        },
        version_minor: {
          value: [0x0004].pack(@byte_order),
          byte: 2
        },
        # 0(GMTのオフセット)からホストのタイムゾーンのオフセットを引く
        thiszone: {
          value: [(0 - Time.now.utc_offset)].pack(@byte_order),
          byte: 4
        },
        # 調査不足のため0で固定
        sigfigs: {
          value: [0x00000000].pack(@byte_order),
          byte: 4
        },
        # 65535に固定
        snaplen: {
          value: [0x0000ffff].pack(@byte_order),
          byte: 4
        },
        network: {
          value: nil,
          byte: 4
        }
      }
      case @protocol
      when 'all'
        pcap_hdr[:network][:value] = [0x00000065].pack(@byte_order)
      end

      @pcap_hdr.each do |key, binary|
        write_file(binary[:value], binary[:byte])
      end
    end

    def packet_convert(frame)
      # packet_data = frame.unpack1('H*').to_i(16)
    end
  end
end
