# frozen_string_literal: true

module RbPacketCapture
  class IPAddr
    def initialize(addr)
      @addr = addr
    end

    def to_s
      @addr.join('.')
    end
  end
end
