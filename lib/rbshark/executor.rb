# frozen_string_literal: true

require 'rbshark/socketer'
require 'rbshark/dumper'

module Rbshark
  class Executor
    def initialize(options)
      @options = options
    end

    def execute
      Rbshark::Dumper.new(@options) if @options.key?('write')
      Rbshark::Socketer.new(@options).start
    rescue StandardError => e
      raise e
    end
  end
end
