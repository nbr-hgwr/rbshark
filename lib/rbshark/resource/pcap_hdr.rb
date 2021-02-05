# frozen_string_literal: true

module Rbshark
  class PcapHeader
    attr_reader :pcap_hdr
    def initialize(magic_number=nil, version_major=nil, version_minor=nil,
                   thiszone=nil, sigfigs=nil, snaplen=nil, network=nil)
      @pcap_hdr = {
        magic_number: {
          value: magic_number,
          byte: 4
        },
        # バージョン2.4で固定
        version_major: {
          value: version_major,
          byte: 2
        },
        version_minor: {
          value: version_minor,
          byte: 2
        },
        # 0(GMTのオフセット)からホストのタイムゾーンのオフセットを引く
        thiszone: {
          value: thiszone,
          byte: 4
        },
        # 調査不足のため0で固定
        sigfigs: {
          value: sigfigs,
          byte: 4
        },
        # 65535に固定
        snaplen: {
          value: snaplen,
          byte: 4
        },
        network: {
          value: network,
          byte: 4
        }
      }
    end
  end
end
