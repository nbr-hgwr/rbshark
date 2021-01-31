# frozen_string_literal: true

module Rbshark
  class PacketHeader
    attr_reader :packet_hdr
    def initialize
      @packet_hdr = {
        # UNIX時刻を記録
        ts_sec: {
          value: nil,
          byte: 4
        },
        # マイクロ秒を記録
        ts_usec: {
          value: nil,
          byte: 4
        },
        # キャプチャしたパケットのバイト数を記録
        incl_len: {
          value: nil,
          byte: 4
        },
        # 実際に保存したパケットのバイト数を記録
        # recvfromの時点で65536bitまでしか受け取らないようにしている
        # そのためorig_lenはincl_lenに合わせる
        orig_len: {
          value: nil,
          byte: 4
        }
      }
    end
  end
end
