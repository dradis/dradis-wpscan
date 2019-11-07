module Dradis
  module Plugins
    module Wpscan
      class Engine < ::Rails::Engine
        isolate_namespace Dradis::Plugins::Wpscan

        include ::Dradis::Plugins::Base
        description 'Processes WPScan JSON output'
        provides :upload
      end
    end
  end
end
