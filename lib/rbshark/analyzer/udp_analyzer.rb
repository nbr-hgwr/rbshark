# frozen_string_literal: true

module Rbshark
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