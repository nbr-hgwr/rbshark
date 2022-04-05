# frozen_string_literal: true

module Rbshark
  class TCPAnalyzer < Analyzer
    attr_reader :th_sport
    attr_reader :th_dport
    attr_reader :th_seq
    attr_reader :th_ack
    attr_reader :th_off # 4bit. tcpヘッダを32bit単位で表現
    attr_reader :th_x2 # 3bit. 常に0
    attr_reader :th_flags # 9bit
    attr_reader :th_win
    attr_reader :th_sum
    attr_reader :th_urp
    attr_reader :th_opt
    attr_reader :th_pad # tcpヘッダが32bit単位であることを保証するために32bit単位になるまで0埋めしてる部分

    def initialize(frame, byte)
      super(frame, byte)

      @th_sport = uint16
      @th_dport = uint16
      @th_seq   = uint32
      @th_ack   = uint32

      # bit数が間違えている
      # 要修正
      @th_off   = (@frame[@byte].ord >> 4) & 0xF
      @th_x2    = (@frame[@byte].ord & 0xF) + ((@frame[@byte + 1].ord >> 2) & 0xF)
      @th_flags = @frame[@byte + 1].ord & 0xF
      @byte = @byte + 2

      @th_win   = uint16
      @th_sum   = uint16
      @th_urp   = uint16

      set_tcp_opt()
    end

    def set_tcp_opt
      opt_size = (@th_off * 4) - 20
      @th_opt  = []
      opt_start_byte = @byte

      while opt_size + opt_start_byte > @byte
        # th_offのbyte分ここで読み込むので、paddingがある場合もここで考慮される
        # paddingがある場合、opt[:type] = 0 で追加されるイメージ
        opt = {
          :type_num => uint8(1),
          :type_name => nil,
          :len  => nil,
          :data => {}
        }

        case opt[:type_num]
        when 0
          # End Of Option List (1Byte)
          opt[:type_name] = 'End Of Option List'
          opt[:len] = 1
        when 1
          # No Operation (1Byte)
          opt[:type_name] = 'No Operation'
          opt[:len] = 1
        when 2
          # MSS (4Byte)
          opt[:type_name] = 'MSS'
          opt[:len] = uint8(1)
          opt[:data][:mss] = uint16
        when 3
          # Window Scale (3Byte)
          opt[:type_name] = 'Window Scale'
          opt[:len] = uint8(1)
          opt[:data][:win_scale] = uint8(1) << 4
        when 4
          # SACK Permitted (2Byte)
          opt[:type_name] = 'SACK Permitted'
          opt[:len] = uint8(1)
        when 5
          # SACK (2+(8*N)byte)
          opt[:type_name] = 'SACK'
          opt[:len] = uint8(1)
          sack_data_len = opt[:len] - 2
          sack_start_byte = @byte
          while sack_data_len + sack_start_byte > @byte
            opt[:data][:sle] = uint32
            opt[:data][:sre] = uint32
          end
        when 8
          # Time Stamp (10byte)
          opt[:type_name] = 'Time Stamp'
          opt[:len] = uint8(1)
          opt[:data][:ts_val] = uint32
          opt[:data][:ts_ecr] = uint32
        end

        @th_opt.push opt
      end

      @th_opt.sort_by!{|x| x[:type_num] }
    end
  end
end