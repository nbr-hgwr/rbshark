# frozen_string_literal: true

module Rbshark
  class PcapHeader
    attr_reader :pcap_hdr
    def initialize()
      @pcap_hdr = {
        magic_number: {
          value: nil,
          byte: 4
        },
        # バージョン2.4で固定
        version_major: {
          value: nil,
          byte: 2
        },
        version_minor: {
          value: nil,
          byte: 2
        },
        # 0(GMTのオフセット)からホストのタイムゾーンのオフセットを引く
        thiszone: {
          value: nil,
          byte: 4
        },
        # 調査不足のため0で固定
        sigfigs: {
          value: nil,
          byte: 4
        },
        # 65535に固定
        snaplen: {
          value: nil,
          byte: 4
        },
        network: {
          value: nil,
          byte: 4
        }
      }
    end

  end
end
