# frozen_string_literal: true

require 'rbshark/executor'
require 'rbshark/version'
require 'optparse'
require 'thor'

module Rbshark
  # CLIで受けたコマンドに対しての処理を行う
  class CLI < Thor
    class_option :interface, type: :string, aliases: '-i', desc: 'specify interface. ex) -i eth0'
    class_option :time, type: :numeric, aliases: '-t', desc: 'specify end time (s). ex) -t 30'
    class_option :write, type: :string, aliases: '-w', desc: 'specify write path. ex) -w hoge.pcap'
    class_option :byte_order, type: :string, aliases: '-b', default: 'little', desc: 'specify byte order. ex) -b [little|big]. default little'
    # class_option :protocol, type: :string, aliases: '-p', default: 'all', desc: 'specify protocol type. ex) -p [all|ipv4|ipv6|arp]'

    default_command :analyse

    def self.exit_on_failure?
      true
    end

    desc 'capture <option>', 'capture and print packet'
    def capture
      unless options.key?('write')
        warn 'Error: file was not specified. -w <write_filte_path>'
        exit(1)
      end
      Rbshark::Executor.new(options).execute
    end

    desc 'dump <option>', 'dump pcap'
    def dump
      Rbshark::Executor.new(options).execute
    end

    desc 'analyse <option>', 'analyse pcap'
    option :read, type: :string, aliases: '-r', desc: 'specify read file. ex) hoge.pcap'
    def analyse
      unless options.key?('read')
        warn 'Error: file was not specified. -r <read_filte_path>'
        exit(1)
      end
      pcap = Rbshark::Reader.new(@options).analyse_pcap
    end
  end
end
