# frozen_string_literal: true

module Rbshark
  class IPV6Addr
    def initialize(addr)
      # To Do: 0が重なっている際に省略できるようにする
      @addr = addr
    end

    def to_s
      @addr.join(':')
    end
  end
end
