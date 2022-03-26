# frozen_string_literal: true

module Rbshark
  class ICMPAnalyzer < Analyzer
    attr_reader :icmp_type
    attr_reader :icmp_code
    attr_reader :icmp_checksum
    attr_reader :icmp_id
    attr_reader :icmp_seq

    def initialize(frame, byte)
      @frame = frame
      @byte = byte

      @icmp_type = uint8(1)
      @icmp_code = uint8(1)
      @icmp_checksum = uint16

      case check_type()
      when 'Echo (ping) Reply', 'Echo (ping) Request'
        @icmp_id = uint16
        @icmp_seq = uint16
      end
    end
  end

  class ICMP4Analyzer < ICMPAnalyzer
    def check_type
      case @icmp_type
      when 0
        'Echo (ping) Reply'
      when 3
        'Destination Unreachable'
      when 4
        'Source Quench'
      when 5
        'Redirect'
      when 8
        'Echo (ping) Request'
      when 11
        'Time Exceeded'
      when 12
        'Parameter Problem'
      when 13
        'Timestamp Request'
      when 14
        'Timestamp Reply'
      when 15
        'Information Request'
      when 16
        'Information Reply'
      when 17
        'Address Mask Request'
      when 18
        'Address Mask Reply'
      end
    end

    def check_code
      # To Do
    end
  end

  class ICMP6Analyzer < ICMPAnalyzer
    def check_type
      case @icmp_type
      when 1
        'Destination Unreachable'
      when 2
        'Packet too Big'
      when 3
        'Time Exceeded'
      when 4
        'Parameter Problem'
      when 128
        'Echo (ping) Request'
      when 129
        'Echo (ping) Reply'
      when 130
        'Multicast Listener Query'
      when 131
        'Multicast Listener Report'
      when 132
        'Multicast Listener Done'
      when 133
        'Router Solicitation'
      when 134
        'Router Advertisement'
      when 135
        'Neighbor Solicitation'
      when 136
        'Neighbor Advertisement'
      when 137
        'Redirect'
      end
    end

    def check_code
      # To Do
    end
  end
end