# frozen_string_literal: true

require 'rbshark/socketer'

module Rbshark
  class Executor
    def initialize(options)
      @options = options
    end

    def execute
      Rbshark::Socketer.new(@options).start
    rescue StandardError => e
      raise e
    end
  end
end
