module Dradis::Plugins::Wpscan
  class Importer < Dradis::Plugins::Upload::Importer
    def self.templates
      { evidence: 'evidence', issue: 'vulnerability' }
    end

    # The framework will call this function if the user selects this plugin from
    # the dropdown list and uploads a file.
    # @returns true if the operation was successful, false otherwise
    def import(params={})

      file_content = File.read( params[:file] )

      # Parse the uploaded file into a Ruby Hash
      logger.info { "Parsing WPScan output from #{ params[:file] }..." }
      data = MultiJson.decode(file_content)
      logger.info { 'Done.' }

      # Do a sanity check to confirm the user uploaded the right file
      # format.
      if data['target_url'].nil?
        error = "ERROR: No 'target_url' field present in the provided " \
                "JSON data. Are you sure you uploaded a WPScan JSON output file?"
        logger.fatal { error }
        content_service.create_note text: error
        return false
      end

      # Initial data normalisation
      data = parse_json( data )

      # Create a node based on the target_url
      node = create_node( data )

      # Parse vulnerability data and make more human readable.
      # NOTE: You need an API token for the WPVulnDB vulnerability data.
      parse_known_vulnerabilities( data, node )


      # Add bespoke/config vulnerabilities to Dradis
      #
      # TODO: Can we add severity to issues?
      #
      # Note: No API key needed.
      parse_config_vulnerabilities( data, node )
    end

    def parse_json( data )
      # Parse scan info data and make more human readable.
      data['wpscan_version']    = data.dig('banner', 'version')
      data['start_time']        = DateTime.strptime(data['start_time'].to_s,'%s')
      data['elapsed']           = "#{data["elapsed"]} seconds"
      data['wordpress_version'] = data.dig('version', 'number')   if data['version']
      data['plugins_string']    = data['plugins'].keys.join("\n") if data['plugins']
      data['themes_string']     = data['themes'].keys.join("\n")  if data['themes']
      data['users']             = data['users'].keys.join("\n")   if data['users']

      data
    end

    def create_node( data )
      node = content_service.create_node(label: data['target_url'], type: :host)

      # Define Node properties
      if node.respond_to?(:properties)
        node.set_property(:start_url, data['target_url'])
        #node.set_property(:start_time, data['start_time'])
        node.set_property(:scan_time, data['elapsed'])
      end

      scan_info = template_service.process_template(template: 'scan_info', data: data)
      content_service.create_note text: scan_info, node: node

      node
    end


    def parse_known_vulnerabilities( data, node )
      vulnerabilities = []

      # WordPress Vulnerabilities
      if data['version'] && data['version']['status'] == 'insecure' || 'outdated'
        data['version']['vulnerabilities'].each do |vulnerability_data|
          vulnerabilities << parse_vulnerability( vulnerability_data )
        end
      end

      # Plugin Vulnerabilities
      if data['plugins']
        data['plugins'].each do |key, plugin|
          if plugin['vulnerabilities']
            plugin['vulnerabilities'].each do |vulnerability_data|
              vulnerabilities << parse_vulnerability( vulnerability_data )
            end
          end
        end
      end

      # Theme Vulnerabilities
      if data['themes']
        data['themes'].each do |key, theme|
          if theme['vulnerabilities']
            theme['vulnerabilities'].each do |vulnerability_data|
              vulnerabilities << parse_vulnerability( vulnerability_data )
            end
          end
        end
      end

      # Add vulnerabilities from WPVulnDB to Dradis
      vulnerabilities.each do |vulnerability|
        logger.info { "Adding vulnerability: #{vulnerability['title']}" }

        vulnerability_template = template_service.process_template(template: 'vulnerability', data: vulnerability)
        issue = content_service.create_issue(text: vulnerability_template, id: vulnerability['wpvulndb_id'], node: node)

        if vulnerability['evidence']
          evidence_content = template_service.process_template(template: 'evidence', data: vulnerability)
          content_service.create_evidence(issue: issue, node: node, content: vulnerability['evidence'])
        end
      end
    end

    def parse_config_vulnerabilities( data, node )
      vulnerabilities = []

      if data['config_backups']
        data['config_backups'].each do |url, value|
          vulnerability = {}
          vulnerability['title']    = 'WordPress Configuration Backup Found'
          vulnerability['evidence'] = url

          vulnerabilities << vulnerability
        end
      end

      if data['db_exports']
        data['db_exports'].each do |url, value|
          vulnerability = {}
          vulnerability['title']    = 'Database Backup File Found'
          vulnerability['evidence'] = url

          vulnerabilities << vulnerability
        end
      end

      if data['timthumbs']
        data['timthumbs'].each do |url, value|
          unless value['vulnerabilities'].empty?
            vulnerability = {}
            vulnerability['title']    = "Timthumb RCE File Found"
            vulnerability['evidence'] = url

            vulnerabilities << vulnerability
          end
        end
      end

      if data['password_attack']
        data['password_attack'].each do |user|
          vulnerability = {}
          vulnerability['title'] = "WordPres Weak User Password Found"
          vulnerability['evidence'] = "#{user[0]}:#{user[1]['password']}"

          vulnerabilities << vulnerability
        end
      end

      # Add WordPress configuration vulnerabilities to Dradis
      vulnerabilities.each do |vulnerability|
        logger.info { "Adding vulnerability: #{vulnerability['title']}" }

        vulnerability_template = template_service.process_template(template: 'vulnerability', data: vulnerability)
        issue = content_service.create_issue(text: vulnerability_template, id: "wpscan_#{rand(999999)}")

        if vulnerability['evidence']
          evidence_content = template_service.process_template(template: 'evidence', data: vulnerability)
          content_service.create_evidence(issue: issue, node: node, content: vulnerability['evidence'])
        end
      end
    end

    def parse_vulnerability( vulnerability_data )
      wpvulndb_url = 'https://wpvulndb.com/vulnerabilities/'

      vulnerability = {}
      vulnerability['title']        = vulnerability_data['title']
      vulnerability['fixed_in']     = vulnerability_data['fixed_in'] if vulnerability_data['fixed_in']
      vulnerability['cve']          = 'CVE-' + vulnerability_data['references']['cve'][0] if vulnerability_data['references']['cve']
      vulnerability['url']          = vulnerability_data['references']['url'].join("\n") if vulnerability_data['references']['url']
      vulnerability['wpvulndb_url'] = wpvulndb_url + vulnerability_data['references']['wpvulndb'][0]
      vulnerability['wpvulndb_id']  = vulnerability_data['references']['wpvulndb'][0]

      vulnerability
    end
  end
end
