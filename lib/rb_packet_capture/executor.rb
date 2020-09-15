require 'rb_packet_capture/socketer'

module RbPacketCapture
  class Executor
    def initialize(cli_opts)
      @cli_opts = cli_opts
    end

    def execute
      RbPacketCapture::Socketer.new(@cli_opts['interface']).start if @cli_opts.include?('interface')
    rescue StandardError => e
      raise e
    end
  end
end
