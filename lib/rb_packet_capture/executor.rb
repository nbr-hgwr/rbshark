require 'rb_packet_capture/soketer'

module RbPacketCapture
  class Executor
    def initialize(cli_opts)
      @cli_opts = cli_opts
    end

    def execute
      PacketCapture::Soketer.new(@cli_opts['interface']) if @cli_opts.include?('interface')
    rescue StandardError => e
      raise e
    end
  end
end
