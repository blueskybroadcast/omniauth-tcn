# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-tcn/version'

Gem::Specification.new do |spec|
  spec.name          = 'omniauth-tcn'
  spec.version       = Omniauth::Tcn::VERSION
  spec.authors       = ['Viktor Leonets']
  spec.email         = ['4405511@gmail.com']
  spec.summary       = %q{TCN SSO}
  spec.description   = %q{TCN SSO}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_dependency 'builder'
  spec.add_dependency 'nokogiri'
  spec.add_dependency 'omniauth', '~> 1.0'
  spec.add_dependency 'omniauth-oauth2', '~> 1.0'
  spec.add_dependency 'rest-client'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
end
