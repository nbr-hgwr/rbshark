# frozen_string_literal: true

require 'fileutils'

module Rbshark
  class Dumper
    attr_reader :offset

    def initialize(options)
      @file_path = options['write']
      @protocol = options['protocol']
      @offset = 0
      case options['byte_order']
      when 'little'
        @byte_order_32 = 'V*'
        @byte_order_16 = 'v*'
      when 'big'
        @byte_order_32 = 'N*'
        @byte_order_16 = 'n*'
      else
        warn 'Error: byte order is incorrect. -b [litte|big]'
        exit(1)
      end

      delete_file(@file_path)
      set_pcap_hdr
    end

    def delete_file(file_path)
      FileUtils.rm(file_path) if File.exist?(file_path)
    end

    def write_file(value, byte)
      File.binwrite(@file_path, value, @offset)
      @offset = @offset + byte
    end

    def set_pcap_hdr
      pcap_hdr = {
        magic_number: {
          value: [0xa1b2c3d4].pack(@byte_order_32),
          byte: 4
        },
        # バージョン2.4で固定
        version_major: {
          value: [0x0002].pack(@byte_order_16),
          byte: 2
        },
        version_minor: {
          value: [0x0004].pack(@byte_order_16),
          byte: 2
        },
        # 0(GMTのオフセット)からホストのタイムゾーンのオフセットを引く
        thiszone: {
          value: [(0 - Time.now.utc_offset)].pack(@byte_order_32),
          byte: 4
        },
        # 調査不足のため0で固定
        sigfigs: {
          value: [0x00000000].pack(@byte_order_32),
          byte: 4
        },
        # 65535に固定
        snaplen: {
          value: [0x0000ffff].pack(@byte_order_32),
          byte: 4
        },
        network: {
          value: [0x00000001].pack(@byte_order_32),
          byte: 4
        }
      }

      pcap_hdr.each do |key, binary|
        write_file(binary[:value], binary[:byte])
      end
    end

    def dump_packet(frame, ts)
      packet_hdr = {
        # UNIX時刻を記録
        ts_sec: {
          value: [ts.to_i.to_s(16).to_i(16)].pack(@byte_order_32),
          byte: 4
        },
        # マイクロ秒を記録
        ts_usec: {
          value: [ts.usec.to_i.to_s(16).to_i(16)].pack(@byte_order_32),
          byte: 4
        },
        # キャプチャしたパケットのバイト数を記録
        incl_len: {
          value: [frame.size.to_s(16).to_i(16)].pack(@byte_order_32),
          byte: 4
        },
        # 実際に保存したパケットのバイト数を記録
        # recvfromの時点で65536bitまでしか受け取らないようにしている
        # そのためorig_lenはincl_lenに合わせる
        orig_len: {
          value: [frame.size.to_s(16).to_i(16)].pack(@byte_order_32),
          byte: 4
        }
      }

      packet_hdr.each do |key, binary|
        write_file(binary[:value], binary[:byte])
      end

      write_file(frame, frame.size)
    end
  end
end
