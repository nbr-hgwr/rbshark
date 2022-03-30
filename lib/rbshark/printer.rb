# frozen_string_literal: true

module Rbshark
  class Printer
    def get_count_space(count)
      space = case count.to_s.length
              when 1
                '          '
              when 2
                '         '
              when 3
                '        '
              when 4
                '       '
              when 5
                '       '
              when 6
                '      '
              else
                '     '
              end
        space
    end

    def print_arp_short(packet_info)
      space = get_count_space(packet_info[:count])

      case packet_info[:msg_type]
      when 'ARP REQUEST'
        puts "#{packet_info[:count]}#{space}#{packet_info[:time_since][0]}   #{packet_info[:src_hrd]} -> #{packet_info[:dst_hrd]} #{packet_info[:msg_type]} Who has #{packet_info[:dst_ip]}? Tell #{packet_info[:src_ip]}"
      when 'ARP REPLY'
        puts "#{packet_info[:count]}#{space}#{packet_info[:time_since][0]}   #{packet_info[:src_hrd]} -> #{packet_info[:dst_hrd]} #{packet_info[:msg_type]} #{packet_info[:src_ip]} is at #{packet_info[:src_hrd]}"
      else
        puts "#{packet_info[:count]}#{space}#{packet_info[:time_since][0]}   #{packet_info[:src_hrd]} -> #{packet_info[:dst_hrd]} #{packet_info[:msg_type]}"
      end
    end

    def print_icmp_short(packet_info)
      space = get_count_space(packet_info[:count])

      # echo reply|request のみidとseqが存在するので分ける
      case packet_info[:msg_type]
      when 'Echo (ping) Reply', 'Echo (ping) Request'
        puts "#{packet_info[:count]}#{space}#{packet_info[:time_since][0]}   #{packet_info[:src_ip]} -> #{packet_info[:dst_ip]} #{packet_info[:pro_type]} #{packet_info[:msg_type]} id=#{packet_info[:id]} seq=#{packet_info[:seq]} ttl=#{packet_info[:ttl]}"
      else
        puts "#{packet_info[:count]}#{space}#{packet_info[:time_since][0]}   #{packet_info[:src_ip]} -> #{packet_info[:dst_ip]} #{packet_info[:pro_type]}"
      end
    end

    def print_icmp6_short(packet_info)
      space = get_count_space(packet_info[:count])

      # echo reply|request のみidとseqが存在するので分ける
      case packet_info[:msg_type]
      when 'Echo (ping) Reply', 'Echo (ping) Request'
        puts "#{packet_info[:count]}#{space}#{packet_info[:time_since][0]}   #{packet_info[:src_ip]} -> #{packet_info[:dst_ip]} #{packet_info[:pro_type]} #{packet_info[:msg_type]} id=#{packet_info[:id]} seq=#{packet_info[:seq]} hop_limit=#{packet_info[:hlim]}"
      else
        puts "#{packet_info[:count]}#{space}#{packet_info[:time_since][0]}   #{packet_info[:src_ip]} -> #{packet_info[:dst_ip]} #{packet_info[:pro_type]} #{packet_info[:msg_type]} hop_limit=#{packet_info[:hlim]}"
      end
    end

    def print_ethernet(ether_header)
      puts 'Ethernet Header-----------------'
      puts "  dst: #{ether_header.ether_dhost}"
      puts "  src: #{ether_header.ether_shost}"
      puts "  type: #{ether_header.ether_type} (#{ether_header.check_protocol_type})"
    end

    def print_arp(arp_header)
      puts 'ARP Header----------------------'
      puts "  [#{arp_header.check_opration}]"
      puts "  sha: #{arp_header.ar_sha}"
      puts "  spa: #{arp_header.ar_sip}"
      puts "  tha: #{arp_header.ar_tha}"
      puts "  tpa: #{arp_header.ar_tip}"
      puts "  arp_hrd: #{arp_header.ar_hrd}"
      puts "  arp_pro: #{arp_header.ar_pro} (#{arp_header.check_protocol_type})"
      puts "  header_len: #{arp_header.ar_hln}"
    end

    def print_ip(ip_header)
      puts 'IP Header-----------------------'
      puts "  dst: #{ip_header.ip_dst}"
      puts "  src: #{ip_header.ip_src}"
      puts "  type: #{ip_header.ip_pro} (#{ip_header.check_protocol_type})"
      puts "  version: #{ip_header.version}, header_len: #{ip_header.ip_hl}, tos: #{ip_header.ip_tos}"
      puts "  len: #{ip_header.ip_len}, id: #{ip_header.ip_id}, flag_off: #{ip_header.ip_off}"
      puts "  ttl: #{ip_header.ip_ttl}, check: #{ip_header.ip_sum}"
    end

    def print_ip6(ip6_header)
      puts 'IPv6 Header-----------------------'
      puts "  dst: #{ip6_header.ip_dst}"
      puts "  src: #{ip6_header.ip_src}"
      puts "  type: #{ip6_header.check_protocol_type}, next header: #{ip6_header.ip_pro}"
      puts "  traffic class: #{ip6_header.ip_traffic_class}"
      puts "  version: #{ip6_header.version}, flow label: #{ip6_header.ip_flow}"
      puts "  plen: #{ip6_header.ip_plen} hop limit: #{ip6_header.ip_hlim}"
    end

    def print_icmp(icmp)
      puts 'ICMP----------------------------'
      puts "  type: #{icmp.icmp_type} (#{icmp.check_type})"
      puts "  code: #{icmp.icmp_code}"
      puts "  check: #{icmp.icmp_checksum}"
      puts "  id: #{icmp.icmp_id}"
      puts "  id: #{icmp.icmp_seq}"
    end

    def print_tcp_short(packet_info, tcp)
      space = get_count_space(packet_info[:count])
      #require 'pry';binding.pry

      packet = "#{packet_info[:count]}#{space}#{packet_info[:time_since][0]}   #{packet_info[:src_ip]} -> #{packet_info[:dst_ip]} #{packet_info[:pro_type]} #{packet_info[:msg_type]} #{tcp.th_sport} > #{tcp.th_dport} Seq=#{tcp.th_seq} Ack=#{tcp.th_ack} Win=#{tcp.th_win}"
      tcp.th_opt.each do |opt|
        case opt[:type_num]
        when 2
          packet += " MSS=#{opt[:data][:mss]}"
        when 3
          packet += " Win_Scale=#{opt[:data][:win_scale]}"
        when 4
          packet += " SACK_PERM=#{opt[:len]}"
        when 5
          packet += " SLE=#{opt[:data][:sle]} SRE=#{opt[:data][:sre]}"
        when 8
          packet += " TSval=#{opt[:data][:ts_val]} TSecr=#{opt[:data][:ts_ecr]}"
        end
      end
      puts packet
    end

    def print_tcp(tcp)
      puts 'TCP-----------------------------'
      puts "  src_port: #{tcp.th_sport}"
      puts "  dst_port: #{tcp.th_dport}"
      puts "  sequence: #{tcp.th_seq}, ack: #{tcp.th_ack}"
      puts "  off_set: #{tcp.th_off}, th_x2: #{tcp.th_x2}"
      puts "  flag: #{tcp.th_flags}, window: #{tcp.th_win}"
      puts "  check: #{tcp.th_sum}, urp: #{tcp.th_urp}"
      puts "  opt:"
      tcp.th_opt.each do |opt|
        next if opt[:type_num] == 0
        puts "    opt type: #{opt[:type_name]} (#{opt[:type_num]})"
        puts "      opt len: #{opt[:len]}"
        case opt[:type_num]
        when 2
          puts "      MSS: #{opt[:data][:mss]}"
        when 3
          puts "      Window Scale: #{opt[:data][:win_scale]}"
        when 4
          puts "      SACK Permmid: #{opt[:len]}"
        when 5
          puts "      SLE start: #{opt[:data][:sle]}"
          puts "      SLE start: #{opt[:data][:sre]}"
        when 8
          puts "      timestamp: #{opt[:data][:ts_val]}"
          puts "      timestamp echo reply: #{opt[:data][:ts_ecr]}"
        end
      end
    end

    def print_udp(udp)
      puts 'UDP-----------------------------'
      puts "  src_port: #{udp.uh_sport}"
      puts "  dst_port: #{udp.uh_dport}"
      puts "  len: #{udp.uh_ulen}, check: #{udp.uh_sum}"
    end
  end
end
