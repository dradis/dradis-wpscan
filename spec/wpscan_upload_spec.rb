require 'spec_helper'

describe 'wpscan upload plugin' do
  describe "Importer" do

    before(:each) do
      # Stub template service
      templates_dir = File.expand_path('../../templates', __FILE__)
      expect_any_instance_of(Dradis::Plugins::TemplateService)
      .to receive(:default_templates_dir).and_return(templates_dir)

      # Init services
      plugin = Dradis::Plugins::Wpscan

      @content_service = Dradis::Plugins::ContentService::Base.new(plugin: plugin)

      @importer = plugin::Importer.new(
        content_service: @content_service
      )
    end

    it 'raises an error note when the json is not valid' do
      expect(@content_service).to receive(:create_note) do |args|
        expect(args[:text]).to include("ERROR: No 'target_url' field present in the provided JSON data")
        OpenStruct.new(args)
      end.once

      @importer.import(file: 'spec/fixtures/files/invalid.json')
    end

    it "creates nodes, issues, notes and an evidences as needed" do
      expect(@content_service).to receive(:create_node) do |args|
        # puts "create_node: #{ args.inspect }"
        expect(args[:label]).to eq('http://www.redacted.com/')
        expect(args[:type]).to eq(:host)
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_note) do |args|
        # puts "create_note: #{ args.inspect }"
        expect(args[:text]).to include("#[Title]#\nWPScan Scan Information")
        expect(args[:node].label).to eq('http://www.redacted.com/')
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_issue) do |args|
        # puts "create_issue: #{ args.inspect }"
        OpenStruct.new(args)
      end.exactly(10).times
      expect(@content_service).to receive(:create_evidence) do |args|
        # puts "create_evidence: #{ args.inspect }"
        OpenStruct.new(args)
      end.exactly(5).times

      # Run the import
      @importer.import(file: 'spec/fixtures/files/sample.json')
    end

  end
end
