# encoding: UTF-8

require 'rubygems'
require 'rdoc/task'
require 'rake/testtask'
require 'rubygems/package_task'

spec = Gem::Specification.new do |s|
  s.name       = "nfnetlink"
  s.version    = "1.0.2"
  s.author     = "Guillaume Delugré"
  s.email      = "guillaume AT security-labs DOT org"
  s.homepage   = "http://github.com/gdelugre/ruby-nfnetlink"
  s.licenses   = [ 'GPL' ]
  s.platform   = Gem::Platform::RUBY
  
  s.summary    = "nfnetlink is a wrapper on top of libnfnetlink using FFI."
  s.description = <<DESC
nfnetlink is a small, still incomplete, wrapper around libnfnetlink. 
DESC

  s.files             = FileList[
    'COPYING', "{lib}/**/*", "{samples}/**/*"
  ]

  s.require_path      = "lib"
  s.has_rdoc          = true
  s.requirements      = "Support for the nfnetlink subsystem in your Linux kernel, libnfnetlink installed and Ruby FFI"

  s.add_dependency('ffi', '>= 0')
end

task :default => [:package]

Gem::PackageTask.new(spec) do |pkg|
  pkg.need_tar = true
end
