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
        content_service: @content_service,
      )
    end

    it "raises an error note when the json is not valid" do
      # Run the import
      p @importer.import(file: 'spec/fixtures/files/invalid.json')
    end

    # it "creates nodes, issues, notes and an evidences as needed" do
    #   expect(@content_service).to receive(:create_node) do |args|
    #     # puts "create_node: #{ args.inspect }"
    #     expect(args[:label]).to eq('74.207.244.221')
    #     expect(args[:type]).to eq(:host)
    #     OpenStruct.new(args)
    #   end.once
    #   expect(@content_service).to receive(:create_note) do |args|
    #     puts "create_note: #{ args.inspect }"
    #     expect(args[:text]).to include("#[Title]#\nWpscan info: 74.207.244.221")
    #     expect(args[:text]).to_not include("not recognized by the plugin")
    #     expect(args[:node].label).to eq("74.207.244.221")
    #     OpenStruct.new(args)
    #   end.once
    #   expect(@content_service).to receive(:create_note) do |args|
    #     puts "create_note: #{ args.inspect }"
    #     expect(args[:text]).to include("#[Title]#\n22/tcp is open (syn-ack)")
    #     expect(args[:text]).to_not include("not recognized by the plugin")
    #     expect(args[:text]).to include("#[Host]#\n74.207.244.221")
    #     expect(args[:node].label).to eq("74.207.244.221")
    #     OpenStruct.new(args)
    #   end.once
    #   expect(@content_service).to receive(:create_note) do |args|
    #     puts "create_note: #{ args.inspect }"
    #     expect(args[:text]).to include("#[Title]#\n80/tcp is open (syn-ack)")
    #     expect(args[:text]).to_not include("not recognized by the plugin")
    #     expect(args[:text]).to include("#[Host]#\n74.207.244.221")
    #     expect(args[:node].label).to eq("74.207.244.221")
    #     OpenStruct.new(args)
    #   end.once

    #   # Run the import
    #   @importer.import(file: 'spec/fixtures/files/sample.json')
    # end

  end
end