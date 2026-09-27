Pod::Spec.new do |s|
  s.name             = 'libetos'
  s.version          = '0.1.0'
  s.summary          = 'libetos'
  s.description      = "libetos"
  s.homepage         = 'https://github.com/foxterm/libetos'
  s.license          = 'MIT'
  s.author           = { 'foxterm' => 'admin@foxterm.app' }
  s.source           = { :git => 'https://github.com/foxterm/libetos.git', :tag => s.version.to_s }
  s.ios.deployment_target = "12.0"
  s.osx.deployment_target = "10.15"
  s.swift_version = '5.10'
  s.source_files = ['Sources/libetos/**/*.{h,c}']
end
