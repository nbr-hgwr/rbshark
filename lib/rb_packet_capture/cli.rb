require 'rb_packet_capture/executor'
require 'rb_packet_capture/version'
require 'optparse'

module RbPacketCapture
  # CLIで受けたコマンドに対しての処理を行う
  class CLI
    class << self
      def parse_options
        opt = OptionParser.new
        opt.version = "exagen: #{RbPacketCapture::VERSION}"

        params = {}

        opt.on '-i INTERFACE', '--interface', 'specify interface' do |v|
          params['interface'] = v
        end

        begin
          opt.parse! ARGV
        rescue StandardError => e
          p "Error: #{e}"
          abort "#{$ERROR_INFO}\n\n#{opt.help}"
        end

        params
      end

      def start
        opts = parse_options
        RbPacketCapture::Executor.new(opts).execute
      end
    end
  end
end
