# frozen_string_literal: true

module Rbshark
  class EthernetAnalyzer < Analyzer
    attr_reader :ether_dhost
    attr_reader :ether_shost
    attr_reader :ether_type

    def initialize(frame, byte = 0)
      @frame = frame
      @byte = byte

      @ether_dhost = MacAddr.new uint8(6)
      @ether_shost = MacAddr.new uint8(6)
      @ether_type = uint16
    end

    def check_protocol_type
      case @ether_type
      when ETH_P_IP
        'IP'
      when ETH_P_IPV6
        'IPv6'
      when ETH_P_ARP
        'ARP'
      else
        'Other'
      end
    end
  end
end