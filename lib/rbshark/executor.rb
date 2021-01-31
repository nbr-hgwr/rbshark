# frozen_string_literal: true

require 'rbshark/socketer'
require 'rbshark/dumper'

module Rbshark
  class Executor
    def initialize(options)
      @options = options
    end

    def execute
      if @options.key?('write')
        pcap = Rbshark::Dumper.new(@options)
        Rbshark::Socketer.new(@options, pcap).start
      else
        Rbshark::Socketer.new(@options).start
      end
    rescue StandardError => e
      raise e
    end
  end
end
