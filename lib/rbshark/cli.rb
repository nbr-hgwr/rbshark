# frozen_string_literal: true

require 'rbshark/executor'
require 'rbshark/version'
require 'rbshark/socketer'
require 'rbshark/dumper'
require 'rbshark/reader'
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

    desc 'dump <option>', 'dump pcap'
    option :print, type: :boolean, aliases: '-p', default: false, desc: 'use print packet'
    option :count, type: :numeric, aliases: '-c', desc: 'specify packet count'
    def dump
      if options.key?('write')
        pcap = Rbshark::Dumper.new(@options)
        Rbshark::Socketer.new(@options, pcap).start
      else
        warn 'Error: file was not specified. -w <write_filte_path>'
        exit(1)
      end
    end

    desc 'analyse <option>', 'analyse pcap'
    option :read, type: :string, aliases: '-r', desc: 'specify read file. ex) hoge.pcap'
    option :print, type: :boolean, aliases: '-p', default: true, desc: 'use print packet'
    def analyse
      unless options.key?('read')
        warn 'Error: file was not specified. -r <read_filte_path>'
        exit(1)
      end
      pcap = Rbshark::Reader.new(@options['read'])
      pcap.packet_data.each do |packet|
        Rbshark::Executor.new(packet[:data], @options['print'])
      end
    end
  end
end
