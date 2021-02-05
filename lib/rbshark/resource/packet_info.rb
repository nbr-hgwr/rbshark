# frozen_string_literal: true

module Rbshark
  class PacketInfo
    attr_reader :packet_info
    def initialize(count, time_since)
      @packet_info = {
        # 何番目にキャプチャされたパケットかを表す番号
        count: count,
        # 最初のパケットがキャプチャされてからの経過時間
        time_since: time_since
      }
    end

    def set_src_hrd(src_hrd)
      @packet_info[:src_hrd] = src_hrd
    end

    def set_dst_hrd(dst_hrd)
      @packet_info[:dst_hrd] = dst_hrd
    end

    def set_src_ip(src_ip)
      @packet_info[:src_ip] = src_ip
    end

    def set_dst_ip(dst_ip)
      @packet_info[:dst_ip] = dst_ip
    end

    def set_pro_type(pro_type)
      @packet_info[:pro_type] = pro_type
    end

    def set_msg_type(msg_type)
      @packet_info[:msg_type] = msg_type
    end

    def set_id(id)
      @packet_info[:id] = id
    end

    def set_seq(seq)
      @packet_info[:seq] = seq
    end

    def set_ttl(ttl)
      @packet_info[:ttl] = ttl
    end

    def set_ether(ether_header)
      set_src_hrd(ether_header.ether_shost)
      set_dst_hrd(ether_header.ether_dhost)
      set_pro_type(ether_header.check_protocol_type) if ether_header.ether_type == 'ARP'
    end

    def set_arp(arp_header)
      set_src_ip(arp_header.ar_sip)
      set_dst_ip(arp_header.ar_tip)
      set_msg_type(arp_header.check_opration)
    end

    def set_ip(ip_header)
      set_pro_type(ip_header.check_protocol_type)
      set_src_ip(ip_header.ip_src)
      set_dst_ip(ip_header.ip_dst)
      set_ttl(ip_header.ip_ttl)
    end

    def set_icmp(icmp)
      set_msg_type(icmp.check_type)
      set_id(icmp.icmp_id)
      set_seq(icmp.icmp_seq)
    end
  end
end
