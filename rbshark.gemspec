# frozen_string_literal: true

require_relative 'lib/rbshark/version'

Gem::Specification.new do |spec|
  spec.name          = 'rbshark'
  spec.version       = Rbshark::VERSION
  spec.authors       = ['nbr-hgwr']

  spec.summary       = 'packet capture tool by Ruby'
  spec.description   = 'packet capture tool by Ruby'
  spec.homepage      = 'https://github.com/nbr-hgwr/rbshark'
  spec.required_ruby_version = Gem::Requirement.new('>= 2.3.0')

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'pry'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'rubocop'
  spec.add_development_dependency 'thor'
end
