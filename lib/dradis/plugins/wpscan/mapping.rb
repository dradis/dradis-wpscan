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
  end
end
