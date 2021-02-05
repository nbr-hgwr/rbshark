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

    def initialize(file_path)
      pcap_data = read_file(file_path)
      @offset = 0
      @pcap_hdr = split_pcap_hdr(pcap_data)

      case @pcap_hdr.pcap_hdr[:magic_number][:value].unpack1('H*')
      when 'a1b2c3d4'
        @byte_order32 = 'N*'
        @byte_order16 = 'n*'
      when 'd4c3b2a1'
        @byte_order32 = 'V*'
        @byte_order16 = 'v*'
      end

      @packet_data = split_packets_data(pcap_data)
    end

    def read_file(file_path)
      if File.exist?(file_path)
        File.binread(file_path)
      else
        warn "Error: #{file_path} dose't exit."
        exit(1)
      end
    end

    def split_pcap_hdr(pcap_data)
      pcap_hdr_binary = pcap_data.byteslice(@offset, 24)
      @offset += 24

      analyse_pcap_hdr(pcap_hdr_binary)
    end

    def split_packets_data(pcap_data)
      packets_data_binary = pcap_data.byteslice(@offset..)
      @offset += packets_data_binary.size

      analyze_packet(packets_data_binary)
    end

    def analyse_pcap_hdr(pcap_hdr_binary)
      pcap_hdr_offset = 0
      pcap_hdr = Rbshark::PcapHeader.new

      pcap_hdr.pcap_hdr.each do |_key, data|
        data[:value] = pcap_hdr_binary.byteslice(pcap_hdr_offset, data[:byte])
        pcap_hdr_offset += data[:byte]
      end

      pcap_hdr
    end

    def analyze_packet(packets_data_binary)
      packet_data_offset = 0

      packet_data = []
      while packets_data_binary.size > packet_data_offset
        packet ={}
        packet[:hdr] = Rbshark::PacketHeader.new

        packet[:hdr].packet_hdr.each do |_key, data|
          data[:value] = packets_data_binary.byteslice(packet_data_offset, data[:byte])
          packet_data_offset += data[:byte]
        end

        orig_len = packet[:hdr].packet_hdr[:orig_len][:value].unpack1(@byte_order32).to_i
        packet[:data] = packets_data_binary.byteslice(packet_data_offset, orig_len)
        packet_data_offset += orig_len
        packet_data << packet
      end

      packet_data
    end
  end
end
