# frozen_string_literal: true

module Rbshark
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
end