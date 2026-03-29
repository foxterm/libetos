Pod::Spec.new do |s|
  s.name             = 'libetos'
  s.version          = '0.1.0'
  s.summary          = 'SSH,libetos'
  s.description      = "libetos + OpenSSL"
  s.homepage         = 'https://github.com/foxterm/libetos'
  s.license          = 'MIT'
  s.author           = { 'foxterm' => 'admin@foxterm.app' }
  s.source           = { :git => 'https://github.com/foxterm/libetos.git', :tag => s.version.to_s }
  s.ios.deployment_target = '17.0'
  s.osx.deployment_target = '14.0'
  s.source_files = ['src/**/*.{c,h}']
  s.public_header_files = ['src/include/*.h']
  s.dependency 'libssh2'
  s.dependency 'OpenSSL-Universal'
end
