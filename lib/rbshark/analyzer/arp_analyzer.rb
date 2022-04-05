# frozen_string_literal: true

module Rbshark
  class ARPAnalyzer < Analyzer
    attr_reader :ar_hrd
    attr_reader :ar_pro
    attr_reader :ar_hln
    attr_reader :ar_pln
    attr_reader :ar_op
    attr_reader :ar_sha
    attr_reader :ar_sip
    attr_reader :ar_tha
    attr_reader :ar_tip

    def initialize(frame, byte)
      super(frame, byte)

      @ar_hrd = uint16
      @ar_pro = uint16
      @ar_hln = uint8(1)
      @ar_pln = uint8(1)
      @ar_op  = uint16
      @ar_sha = MacAddr.new uint8(6)
      @ar_sip = IPV4Addr.new uint8(4)
      @ar_tha = MacAddr.new uint8(6)
      @ar_tip = IPV4Addr.new uint8(4)
    end

    def check_protocol_type
      case @ar_pro
      when ETH_P_IP
        'IP'
      else
        'Other'
      end
    end

    def check_opration
      case @ar_op
      when 1
        'ARP REQUEST'
      when 2
        'ARP REPLY'
      when 3
        'RARP REQUEST'
      when 4
        'RARP REPLY'
      when 8
        'InARP REQUEST'
      when 9
        'InARP REPLY'
      when 10
        'ARP NAK'
      end
    end
  end
end