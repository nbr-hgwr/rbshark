# frozen_string_literal: true

module Rbshark
  class IPAnalyzer < Analyzer
    def initialize(frame, byte)
      super(frame, byte)

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

    def validate_cksum
      ip_header = @frame[@start_byte..@byte]
      ip_header_bytes = @byte - @start_byte
      @byte = @start_byte
      sum = 0
      for i in 1..ip_header_bytes/2
        sum += uint16
      end
      sum = sum.to_s(16)
      sum = sum[0].to_i(16) + sum[1..4].to_i(16)
      if sum.to_s(16) == 'ffff'
        true
      else
        false
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
    attr_reader :vali_sum

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

      @vali_sum = validate_cksum()
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
end