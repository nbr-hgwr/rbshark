# frozen_string_literal: true

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
end
