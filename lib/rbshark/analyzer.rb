# frozen_string_literal: true

require 'rbshark/resource/type'

module Rbshark
  class Analyzer
    def uint8(size)
      binary = if size == 1
            @frame[@byte].ord
          else
            @frame[@byte...@byte + size].split('').map { |c| c.ord }
          end
      @byte += size
      binary
    end

    def uint16
      binary = (@frame[@byte].ord << 8) + @frame[@byte + 1].ord
      @byte += 2
      binary
    end

    def uint32
      binary = (@frame[@byte].ord << 8) + @frame[@byte + 1].ord + @frame[@byte + 2].ord + @frame[@byte + 3].ord
      @byte += 4
      binary
    end

    def separate_ipv6
      binary = []
      for i in 0..7
        binary.push ((@frame[@byte].ord << 8) + @frame[@byte+1].ord).to_s(16)
        @byte += 2
      end

      binary
    end

    def return_byte
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

  class IPAnalyzer < Analyzer
    def initialize(frame, byte)
      @frame = frame
      @byte = byte

      # プロトコル種別を定義
      # To Do: 量が多いのでhashとして持たせたくないので直す
      # 一度hashで書いてしまい直すのが面倒になってしまった...
      @type = {
        '0' => 'HOPOPT',
        '1' => 'ICMP',
        '2' => 'IGMP',
        '3' => 'GGP',
        '4' => 'IP-in-IP',
        '5' => 'ST',
        '6' => 'TCP',
        '7' => 'CBT',
        '8' => 'EGP',
        '9' => 'IGP',
        '10' => 'BBN-RCC-MON',
        '11' => 'NVP-II',
        '12' => 'PUP',
        '13' => 'ARGUS',
        '14' => 'EMCON',
        '15' => 'XNET',
        '16' => 'CHAOS',
        '17' => 'UDP',
        '18' => 'MUX',
        '19' => 'DCN-MEAS',
        '20' => 'HMP',
        '21' => 'PRM',
        '22' => 'XNS-IDP',
        '23' => 'TRUNK-1',
        '24' => 'TRUNK-2',
        '25' => 'LEAF-1',
        '26' => 'LEAF-2',
        '27' => 'RDP',
        '28' => 'IRTP',
        '29' => 'ISO-TP4',
        '30' => 'NETBLT',
        '31' => 'MFE-NSP',
        '32' => 'MERIT-INP',
        '33' => 'DCCP',
        '34' => '3PC',
        '35' => 'IDPR',
        '36' => 'XTP',
        '37' => 'DDP',
        '38' => 'IDPR-CMTP',
        '39' => 'TP++',
        '40' => 'IL',
        '41' => 'IPv6',
        '42' => 'SDRP',
        '43' => 'IPv6-Route',
        '44' => 'IPv6-Frag',
        '45' => 'IDRP',
        '46' => 'RSVP',
        '47' => 'GREs',
        '48' => 'DSR',
        '49' => 'BNA',
        '50' => 'ESP',
        '51' => 'AH',
        '52' => 'I-NLSP',
        '53' => 'SWIPE',
        '54' => 'NARP',
        '55' => 'MOBILE',
        '56' => 'TLSP',
        '57' => 'SKIP',
        '58' => 'ICMP6',
        '59' => 'IPv6-NoNxt',
        '60' => 'IPv6-Opts',
        '61' => 'Internal-Protocol',
        '62' => 'CFTP',
        '63' => 'Local-Network',
        '64' => 'SAT-EXPAK',
        '65' => 'KRYPTOLAN',
        '66' => 'RVD',
        '67' => 'IPPC',
        '68' => 'Distributed-File-System',
        '69' => 'SAT-MON',
        '70' => 'VISA',
        '71' => 'IPCV',
        '72' => 'CPNX',
        '73' => 'CPHB',
        '74' => 'WSN',
        '75' => 'PVP',
        '76' => 'BR-SAT-MON',
        '77' => 'SUN-ND',
        '78' => 'WB-MON',
        '79' => 'WB-EXPAK',
        '80' => 'ISO-IP',
        '81' => 'VMTP',
        '82' => 'SECURE-VMTP',
        '83' => 'VINES',
        '84' => 'TTP',
        '85' => 'NSFNET-IGP',
        '86' => 'DGP',
        '87' => 'TCF',
        '88' => 'EIGRP',
        '89' => 'OSPFIGP',
        '90' => 'Sprite-RPC',
        '91' => 'LARP',
        '92' => 'MTP',
        '93' => 'AX.25',
        '94' => 'IPIP',
        '95' => 'MICP',
        '96' => 'SCC-SP',
        '97' => 'ETHERIP',
        '98' => 'ENCAP',
        '99' => 'Private-Encryption-Scheme',
        '100' => 'GMTP',
        '101' => 'IFMP',
        '102' => 'PNNI',
        '103' => 'PIM',
        '104' => 'ARIS',
        '105' => 'SCPS',
        '106' => 'QNX',
        '107' => 'A/N',
        '108' => 'IPComp',
        '109' => 'SNP',
        '110' => 'Compaq-Peer',
        '111' => 'IPX-in-IP',
        '112' => 'VRRP',
        '113' => 'PGM',
        '114' => '0-Hop-Protocol',
        '115' => 'L2TP',
        '116' => 'DDX',
        '117' => 'IATP',
        '118' => 'STP',
        '119' => 'SRP',
        '120' => 'UTI',
        '121' => 'SMP',
        '122' => 'SM',
        '123' => 'PTP',
        '124' => 'ISIS over IPv4',
        '125' => 'FIRE',
        '126' => 'CRTP',
        '127' => 'CRUDP',
        '128' => 'SSCOPMCE',
        '129' => 'IPLT',
        '130' => 'SPS',
        '131' => 'PIPE',
        '132' => 'SCTP',
        '133' => 'FC',
        '134' => 'RSVP-E2E-IGNORE',
        '135' => 'Mobility Header',
        '136' => 'UDPLite',
        '137' => 'MPLS-in-IP',
        '138' => 'manet',
        '139' => 'HIP',
        '140' => 'Shim6',
        '141' => 'WESP',
        '142' => 'ROHC'
      }
    end

    def check_protocol_type
      case @ip_pro
      when 0...142
        @type[@ip_pro.to_s]
      else
        'Unknown'
      end
    end
  end

  class IPV4Analyzer < IPAnalyzer
    attr_reader :version
    attr_reader :ip_hl
    attr_reader :ip_tos
    attr_reader :ip_len
    attr_reader :ip_id
    attr_reader :ip_off
    attr_reader :ip_ttl
    attr_reader :ip_pro
    attr_reader :ip_sum
    attr_reader :ip_src
    attr_reader :ip_dst

    def initialize(frame, byte)
      super(frame, byte)

      @version = (@frame[@byte].ord >> 4) & 0xF
      @ip_hl = @frame[@byte].ord & 0xF
      @byte += 1

      @ip_tos = uint8(1)
      @ip_len = uint16
      @ip_id = uint16
      @ip_off = uint16
      @ip_ttl = uint8(1)
      @ip_pro = uint8(1)
      @ip_sum = uint16
      @ip_src = IPV4Addr.new uint8(4)
      @ip_dst = IPV4Addr.new uint8(4)
    end
  end

  class IPV6Analyzer < IPAnalyzer
    attr_reader :version
    attr_reader :ip_traffic_class
    attr_reader :ip_flow
    attr_reader :ip_plen
    attr_reader :ip_pro # 本来はip_nxtであるが check_protocol_type()のためにv4/v6で変数名を合わせている
    attr_reader :ip_hlim
    attr_reader :ip_src
    attr_reader :ip_dst

    def initialize(frame, byte)
      super(frame, byte)

      @version = (@frame[@byte].ord >> 4) & 0xF
      @ip_traffic_class = @frame[@byte].ord & 0xF + (@frame[@byte + 1].ord >> 4) & 0xF
      @byte += 2

      @ip_flow = (@frame[@byte].ord & 0xF) + uint16
      @ip_plen = uint16
      @ip_pro = uint8(1)
      @ip_hlim = uint8(1)
      @ip_src = IPV6Addr.new separate_ipv6
      @ip_dst = IPV6Addr.new separate_ipv6
    end
  end

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
end
