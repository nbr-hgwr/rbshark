# frozen_string_literal: true

module Rbshark
  # パケットのバイナリデータを解析するためのクラス
  class Analyzer
    # 8の倍数のbit分のデータを数値に変換して返す
    # size=1の場合は数値を返す
    # size>2の場合は8bitずつ数値にし配列にして返す
    def uint8(size)
      binary = if size == 1
            @frame[@byte].ord
          else
            @frame[@byte...@byte + size].split('').map { |c| c.ord }
          end
      @byte += size
      binary
    end

    # 16bitのデータを数値に変換して返す
    def uint16
      binary = (@frame[@byte].ord << 8) + @frame[@byte + 1].ord
      @byte += 2
      binary
    end

    # 32bitのデータを数値に変換して返す
    def uint32
      binary = (@frame[@byte].ord << 24) + (@frame[@byte + 1].ord << 16) + (@frame[@byte + 2].ord << 8 ) + @frame[@byte + 3].ord
      @byte += 4
      binary
    end

    # 128bitのipv6アドレスが格納されているデータを数値に変換して返す
    def separate_ipv6
      binary = []
      for i in 0..7
        binary.push ((@frame[@byte].ord << 8) + @frame[@byte+1].ord).to_s(16)
        @byte += 2
      end

      binary
    end

    # 現在解析が完了しているByte数を返す
    def return_byte
      @byte
    end
  end
end
