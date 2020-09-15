# frozen_string_literal: true

require 'rb_packet_capture/resource/type'

module RbPacketCapture
  class Analyzer

    def uint8(size)
      if size == 1
        r = @frame[@byte].ord
      else
        r = @frame[@byte...@byte + size].split('').map { |c| c.ord }
      end
      @byte += size
      r
    end

    def uint16
      r = (@frame[@byte].ord << 8) + @frame[@byte + 1].ord
      @byte += 2
      r
    end

    def uint32
      r = (@frame[@byte].ord << 8) + @frame[@byte + 1].ord + @frame[@byte + 2].ord + @frame[@byte + 3].ord
      @byte += 4
      r
    end

    def get_byte
      @byte
    end
  end

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
      @frame = frame
      @byte = byte

      @ar_hrd = uint16
      @ar_pro = uint16
      @ar_hln = uint8(1)
      @ar_pln = uint8(1)
      @ar_op  = uint16
      @ar_sha = MacAddr.new uint8(6)
      @ar_sip = IPAddr.new uint8(4)
      @ar_tha = MacAddr.new uint8(6)
      @ar_tip = IPAddr.new uint8(4)
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

  class IPAnalyzer < Analyzer
    attr_reader :version
    attr_reader :ip_hl
    attr_reader :ip_tos
    attr_reader :ip_len
    attr_reader :ip_id
    attr_reader :ip_off
    attr_reader :ip_ttl
    attr_reader :ip_p
    attr_reader :ip_sum
    attr_reader :ip_src
    attr_reader :ip_dst

    def initialize(frame, byte)
      @frame = frame
      @byte = byte

      @version = (@frame[@byte].ord >> 4) & 0xF
      @ip_hl = @frame[@byte].ord & 0xF
      @byte += 1

      @ip_tos = uint8(1)
      @ip_len = uint16
      @ip_id = uint16
      @ip_off = uint16
      @ip_ttl = uint8(1)
      @ip_p = uint8(1)
      @ip_sum = uint16
      @ip_src = IPAddr.new uint8(4)
      @ip_dst = IPAddr.new uint8(4)
    end

    def check_protocol_type
      case @ip_p
      when 1
        'ICMP'
      when 6
        'TCP'
      when 17
        'UDP'
      else
        'Other'
      end
    end

  end

  class ICMPAnalyzer < Analyzer
    attr_reader :icmp_type
    attr_reader :icmp_code
    attr_reader :icmp_checksum

    def initialize(frame, byte)
      @frame = frame
      @byte = byte

      @icmp_type = uint8(1)
      @icmp_code = uint8(1)
      @icmp_checksum = uint16
    end

    def check_type
      case @icmp_type
      when 0
        'Echo Reply'
      when 3
        'Destination Unreachable'
      when 4
        'Source Quench'
      when 5
        'Redirect'
      when 8
        'Echo Request'
      when 11
        'Time Exceeded '
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

  class TCPAnalyzer < Analyzer
    attr_reader :th_sport
    attr_reader :th_dport
    attr_reader :th_seq
    attr_reader :th_ack
    attr_reader :th_off
    attr_reader :th_x2
    attr_reader :th_flags
    attr_reader :th_win
    attr_reader :th_sum
    attr_reader :th_urp

    def initialize(frame, byte)
      @frame = frame
      @byte = byte

      @th_sport = uint16
      @th_dport = uint16
      @th_seq   = uint32
      @th_ack   = uint32

      @th_off   = (@frame[@byte].ord >> 4) & 0xF
      @th_x2    = (@frame[@byte].ord & 0xF) + ((@frame[@byte + 1].ord >> 2) & 0xF)
      @th_flags = @frame[@byte + 1].ord & 0xF
      @byte = byte + 2
      @byte += 2

      @th_win   = uint16
      @th_sum   = uint16
      @th_urp   = uint16
    end
  end

  class UDPAnalyzer < Analyzer
    attr_reader :uh_sport
    attr_reader :uh_dport
    attr_reader :uh_ulen
    attr_reader :uh_sum

    def initialize(frame, byte)
      @frame = frame
      @byte = byte

      @uh_sport = uint16
      @uh_dport = uint16
      @uh_ulen  = uint16
      @uh_sum   = uint16
    end
  end

  class IPV6Analyzer < Analyzer
    attr_reader :version
    attr_reader :ip_hl
    attr_reader :ip_tos
    attr_reader :ip_len
    attr_reader :ip_id
    attr_reader :ip_off
    attr_reader :ip_ttl
    attr_reader :ip_p
    attr_reader :ip_sum
    attr_reader :ip_src
    attr_reader :ip_dst

    def initialize(frame, byte)
      @frame = frame
      @byte = byte

      @version = (@frame[@byte].ord >> 4) & 0xF
      @ip_hl = @frame[@byte].ord & 0xF
      @byte +=1

      @ip_tos = uint8(1)
      @ip_len = uint16
      @ip_id = uint16
      @ip_off = uint16
      @ip_ttl = uint8(1)
      @ip_p = uint8(1)
      @ip_sum = uint16
      @ip_src = IPAddr.new uint8(4)
      @ip_dst = IPAddr.new uint8(4)
    end

    def check_protocol_type
      case @ip_p
      when 1
        'ICMP'
      when 6
        'TCP'
      when 22
        'UDP'
      else
        'Other'
      end
    end
  end
end
