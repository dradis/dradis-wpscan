module Dradis::Plugins::Wpscan
  module Mapping
    DEFAULT_MAPPING = {
      evidence: {
        'Evidence' => '{{ wpscan[evidence.evidence] }}'
      },
      scan_info: {
        'Title' => 'WPScan Scan Information',
        'TargetURL' => '{{ wpscan[scan_info.target_url] }}',
        'WordpressVersion' => '{{ wpscan[scan_info.wordpress_version] }}',
        'Plugins' => '{{ wpscan[scan_info.plugins_string] }}',
        'Themes' => '{{ wpscan[scan_info.themes_string] }}',
        'Users' => '{{ wpscan[scan_info.users] }}',
        'WPScanVersion' => '{{ wpscan[scan_info.wpscan_version] }}',
        'StartTime' => '{{ wpscan[scan_info.start_time] }}',
        'TotalScanTime' => '{{ wpscan[scan_info.elapsed] }}'
      },
      vulnerability: {
        'Title' => '{{ wpscan[vulnerability.title] }}',
        'FixedIn' => '{{ wpscan[vulnerability.fixed_in] }}',
        'CVE' => '{{ wpscan[vulnerability.cve] }}',
        'References' => '{{ wpscan[vulnerability.url] }}',
        'WPVulnDB' => '{{ wpscan[vulnerability.wpvulndb_url] }}'
      }
    }.freeze

    SOURCE_FIELDS = {
      evidence: [
        'evidence.evidence'
      ],
      scan_info: [
        'scan_info.target_url',
        'scan_info.wpscan_version',
        'scan_info.start_time',
        'scan_info.elapsed',
        'scan_info.wordpress_version',
        'scan_info.plugins_string',
        'scan_info.themes_string',
        'scan_info.users'
      ],
      vulnerability: [
        'vulnerability.title',
        'vulnerability.fixed_in',
        'vulnerability.cve',
        'vulnerability.url',
        'vulnerability.wpvulndb_url',
        'vulnerability.wpvulndb_id'
      ]
    }.freeze
  end
end
