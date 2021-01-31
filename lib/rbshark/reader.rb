# frozen_string_literal: true

require 'rbshark/resource/pcap_hdr'
require 'rbshark/resource/packet_hdr'
require 'fileutils'


module Rbshark
  class Reader
    attr_reader :pcap_hdr
    attr_reader :packet_data
    attr_reader :byte_order32
    attr_reader :byte_order16

    def initialize(options)
      @pcap_data = read_file(options['read'])
      @offset = 0
    end

    def read_file(file_path)
      if File.exist?(file_path)
        File.binread(file_path)
      else
        warn "Error: #{file_path} dose't exit."
        exit(1)
      end
    end

    def analyse_pcap
      pcap_hdr_binary = @pcap_data.byteslice(@offset, 24)
      @offset = @offset + 24

      packets_data_binary = @pcap_data.byteslice(@offset..)
      @offset = @offset + packets_data_binary.size

      analyse_pcap_hdr(pcap_hdr_binary)
      analyze_packet(packets_data_binary)
    end

    def analyse_pcap_hdr(pcap_hdr_binary)
      pcap_hdr_offset = 0
      @pcap_hdr = Rbshark::PcapHeader.new()

      @pcap_hdr.pcap_hdr.each do |key, data|
        data[:value] = pcap_hdr_binary.byteslice(pcap_hdr_offset, data[:byte])
        pcap_hdr_offset = pcap_hdr_offset + data[:byte]
      end

      case @pcap_hdr.pcap_hdr[:magic_number][:value].unpack('H*').first
      when 'a1b2c3d4'
        @byte_order32 = 'N*'
        @byte_order16 = 'n*'
      when 'd4c3b2a1'
        @byte_order32 = 'V*'
        @byte_order16 = 'v*'
      end
    end

    def analyze_packet(packets_data_binary)
      packet_data_offset = 0

      @packet_data = []
      while packets_data_binary.size > packet_data_offset
        packet ={}
        packet[:hdr] = Rbshark::PacketHeader.new()

        packet[:hdr].packet_hdr.each do |key, data|
          data[:value] = packets_data_binary.byteslice(packet_data_offset, data[:byte])
          packet_data_offset = packet_data_offset + data[:byte]
        end

        orig_len = packet[:hdr].packet_hdr[:orig_len][:value].unpack(@byte_order32).first.to_i
        packet[:data] = packets_data_binary.byteslice(packet_data_offset, orig_len)
        packet_data_offset = packet_data_offset + orig_len
        @packet_data << packet
      end
      packet_data
    end

  end
end