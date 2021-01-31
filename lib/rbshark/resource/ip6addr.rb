# frozen_string_literal: true

module Rbshark
  class IPV6Addr
    def initialize(addr)
      @addr = addr
    end

    def to_s
      @addr.join(':')
    end
  end
end
