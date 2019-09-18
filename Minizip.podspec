Pod::Spec.new do |s|
  s.name     = 'Minizip'
  s.version  = '2.9.0'
  s.license  = 'zlib'
  s.summary  = 'Minizip contrib in zlib with the latest bug fixes and advanced features'
  s.description = <<-DESC
Minizip zlib contribution that includes:
* AES encryption
* I/O buffering
* PKWARE disk splitting
It also has the latest bug fixes that having been found all over the internet.
DESC
  s.homepage = 'https://github.com/nmoinvaz/minizip'
  s.authors = 'Nathan Moinvaziri', 'Gilles Vollant'

  s.source   = { :git => 'https://github.com/nmoinvaz/minizip.git', :tag => "#{s.version}" }
  s.libraries = 'z', 'iconv'
  s.default_subspecs = 'Core', 'PKCRYPT', 'WZAES_APPLE', 'BZIP2'

  s.subspec 'Core' do |sp|
    sp.source_files = '{mz,mz_os,mz_os_posix,mz_compat,mz_crypt,mz_strm,mz_strm_mem,mz_strm_buf,mz_strm_crypt,mz_strm_os_posix,mz_strm_zlib,mz_zip}.{c,h}'
    sp.pod_target_xcconfig = { 'GCC_PREPROCESSOR_DEFINITIONS' => 'HAVE_INTTYPES_H HAVE_STDINT_H HAVE_ZLIB' }
  end

  s.subspec 'PKCRYPT' do |sp|
    # Enables PKWARE traditional encryption
    sp.dependency 'Minizip/Core'
    sp.source_files = 'mz_strm_pkcrypt.{c,h}'
    sp.pod_target_xcconfig = { 'GCC_PREPROCESSOR_DEFINITIONS' => 'HAVE_PKCRYPT' }
  end

  s.subspec 'WZAES_APPLE' do |sp|
    # Enables Apple's Security framework for AES
    sp.dependency 'Minizip/Core'
    sp.source_files = 'mz_strm_wzaes.{c,h}', 'mz_crypt_apple.c'
    sp.framework = 'Security'
    sp.pod_target_xcconfig = { 'GCC_PREPROCESSOR_DEFINITIONS' => 'HAVE_WZAES' }
  end

  s.subspec 'WZAES_BRG' do |sp|
    # Enables Brian Gladman's encryption library for AES
    sp.dependency 'Minizip/Core'
    sp.source_files = 'lib/brg/*.{c,h}', 'mz_strm_wzaes.{c,h}', 'mz_crypt_brg.c'
    sp.pod_target_xcconfig = { 'GCC_PREPROCESSOR_DEFINITIONS' => 'HAVE_ARC4RANDOM_BUF HAVE_WZAES' }
  end

  s.subspec 'BZIP2' do |sp|
    # Enables BZIP2 compression
    sp.dependency 'Minizip/Core'
    sp.source_files = 'lib/bzip2/*.{c,h}', 'mz_strm_bzip.{c,h}'
    sp.pod_target_xcconfig = { 'GCC_PREPROCESSOR_DEFINITIONS' => 'HAVE_BZIP2' }
  end

  s.subspec 'LZMA' do |sp|
    # Enables LZMA compression
    sp.dependency 'Minizip/Core'
    sp.source_files = 'lib/liblzma/**/*.{c,h}', 'mz_strm_lzma.{c,h}'
    sp.pod_target_xcconfig = { 'GCC_PREPROCESSOR_DEFINITIONS' => 'HAVE_LZMA' }
  end
end
