# frozen_string_literal: true

require 'rbshark/executor'
require 'rbshark/version'
require 'optparse'
require 'thor'

module Rbshark
  # CLIで受けたコマンドに対しての処理を行う
  class CLI < Thor
    class_option :interface, :type => :string, :aliases => '-i', :desc => 'specify interface'
    default_command :analyse

    def self.exit_on_failure?
      true
    end

    desc 'capture <option>', 'capture and print packet'
    def capture
      Rbshark::Executor.new(options).execute
    end

    desc 'dump <option>', 'dump pcap'
    def dump
      Rbshark::Executor.new(options).execute
    end

    desc 'analyse <option>', 'analyse pcap'
    def analyse
      Rbshark::Executor.new(options).execute
    end
  end
end
