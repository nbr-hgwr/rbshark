# frozen_string_literal: true

module Rbshark
  class ICMP6
    def initialize(frame)
      Type = {
        :1 => 'Destination Unreachable'
      }
    end

    def to_s
      @addr.join('.')
    end
  end
end
