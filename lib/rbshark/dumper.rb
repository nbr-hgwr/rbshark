# frozen_string_literal: true

require 'fileutils'

module Rbshark
  class Dumper
    attr_reader :offset
    attr_reader :byte_order32
    attr_reader :byte_order16

    def initialize(options)
      @file_path = options['write']
      @protocol = options['protocol']
      @offset = 0
      case options['byte_order']
      when 'little'
        @byte_order32 = 'V*'
        @byte_order16 = 'v*'
      when 'big'
        @byte_order32 = 'N*'
        @byte_order16 = 'n*'
      else
        warn 'Error: byte order is incorrect. -b [litte|big]'
        exit(1)
      end
    end

    def dump_pcap_hdr
      delete_file(@file_path)
      pcap_hdr = set_pcap_hdr

      pcap_hdr.pcap_hdr.each do |_key, binary|
        write_file(binary[:value], binary[:byte])
      end
    end

    def delete_file(file_path)
      FileUtils.rm(file_path) if File.exist?(file_path)
    end

    def write_file(value, byte)
      File.binwrite(@file_path, value, @offset)
      @offset += byte
    end

    def set_pcap_hdr
      pcap_hdr = Rbshark::PcapHeader.new(
        [0xa1b2c3d4].pack(@byte_order32),
        [0x0002].pack(@byte_order16),
        [0x0004].pack(@byte_order16),
        [(0 - Time.now.utc_offset)].pack(@byte_order32),
        [0x00000000].pack(@byte_order32),
        [0x0000ffff].pack(@byte_order32),
        [0x00000001].pack(@byte_order32)
      )
    end

    def set_packet_hdr(frame, timestamp)
      packet_hdr = Rbshark::PacketHeader.new(
        [timestamp.to_i.to_s(16).to_i(16)].pack(@byte_order32),
        [timestamp.usec.to_i.to_s(16).to_i(16)].pack(@byte_order32),
        [frame.size.to_s(16).to_i(16)].pack(@byte_order32),
        [frame.size.to_s(16).to_i(16)].pack(@byte_order32)
      )
    end

    def dump_packet(frame, timestamp)
      packet_hdr = set_packet_hdr(frame, timestamp)

      packet_hdr.packet_hdr.each do |_key, binary|
        write_file(binary[:value], binary[:byte])
      end

      write_file(frame, frame.size)
    end
  end
end
