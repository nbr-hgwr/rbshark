# frozen_string_literal: true

module Rbshark
  class IPAddr
    def initialize(addr)
      # To Do: 0が重なっている際に省略できるようにする
      @addr = addr
    end
  end

  class IPV4Addr < IPAddr
    def to_s
      @addr.join(':')
    end
  end

  class IPV6Addr < IPAddr
    def to_s
      @addr.join('.')
    end
  end
end
