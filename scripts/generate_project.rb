#!/usr/bin/env ruby
# Generates Fathom.xcodeproj from the sources on disk.
#
# The project file is generated rather than committed so that adding a Swift file or a
# runtime source never involves hand-editing a pbxproj, and so the FEXCore header search
# paths stay in exactly one place: here.

require 'xcodeproj'
require 'fileutils'

PROJECT_NAME = 'Fathom'
REPO_ROOT = File.expand_path('..', __dir__)
APP_DIR = File.join(REPO_ROOT, PROJECT_NAME)
PROJECT_PATH = File.join(APP_DIR, "#{PROJECT_NAME}.xcodeproj")

# Must match DEPLOYMENT_TARGET in build-fexcore-ios.sh: libFEXCore.a's object code is
# compiled against this floor, and disagreeing here is inconsistent metadata at best.
DEPLOYMENT_TARGET = '18.0'

FEXCORE_SRC = ENV.fetch(
  'FEXCORE_SRC',
  File.join(Dir.home, 'Documents/Coding/fathom-fexcore/runtime/sources/fexcore-darwin')
)
FEXCORE_BUILD = ENV.fetch('FEXCORE_BUILD', File.join(REPO_ROOT, 'build/fexcore-ios'))

unless Dir.exist?(FEXCORE_SRC)
  abort "error: FEXCore sources not found at #{FEXCORE_SRC}\n" \
        "       run scripts/build-fexcore-ios.sh first, or set FEXCORE_SRC"
end

libraries = Dir.glob(File.join(APP_DIR, 'Libs', '*.a')).sort
if libraries.empty?
  abort "error: no static libraries in #{APP_DIR}/Libs -- run scripts/build-fexcore-ios.sh first"
end

FileUtils.rm_rf(PROJECT_PATH)
project = Xcodeproj::Project.new(PROJECT_PATH)
target = project.new_target(:application, PROJECT_NAME, :ios, DEPLOYMENT_TARGET)

# --- Swift sources -----------------------------------------------------------------

sources_group = project.main_group.new_group('Sources', 'Sources')
%w[App Models Views].each do |folder|
  group = sources_group.new_group(folder, folder)
  Dir.glob(File.join(APP_DIR, 'Sources', folder, '*.swift')).sort.each do |file|
    target.add_file_references([group.new_file(File.absolute_path(file))])
  end
end

# --- Emulator core (C++) -----------------------------------------------------------

runtime_group = sources_group.new_group('Runtime', 'Runtime')
Dir.glob(File.join(APP_DIR, 'Sources', 'Runtime', '*.cpp')).sort.each do |file|
  target.add_file_references([runtime_group.new_file(File.absolute_path(file))])
end
Dir.glob(File.join(APP_DIR, 'Sources', 'Runtime', '*.h')).sort.each do |file|
  runtime_group.new_file(File.absolute_path(file))
end

# --- Static libraries --------------------------------------------------------------

libs_group = project.main_group.new_group('Libs', 'Libs')
libraries.each do |library|
  target.frameworks_build_phase.add_file_reference(libs_group.new_file(File.absolute_path(library)), true)
end

target.frameworks_build_phase.add_file_reference(
  project.frameworks_group.new_file('usr/lib/libc++.tbd', :sdk_root), true
)

# --- Resources ---------------------------------------------------------------------

resources_group = project.main_group.new_group('Resources', 'Resources')
target.resources_build_phase.add_file_reference(
  resources_group.new_file(File.absolute_path(File.join(APP_DIR, 'Resources', 'Assets.xcassets')))
)
# StikDebug's Universal JIT Script, handed to StikDebug over its URL scheme when Fathom
# asks for JIT. Shipped as a file so it can be replaced with a newer one by dropping it
# in, rather than being re-encoded into a Swift literal.
target.resources_build_phase.add_file_reference(
  resources_group.new_file(File.absolute_path(File.join(APP_DIR, 'Resources', 'guest-rootfs.tar')))
)

target.resources_build_phase.add_file_reference(
  resources_group.new_file(File.absolute_path(File.join(APP_DIR, 'Resources', 'universal.js')))
)
project.main_group.new_file(File.absolute_path(File.join(APP_DIR, 'Info.plist')))
project.main_group.new_file(File.absolute_path(File.join(APP_DIR, 'Fathom-Bridging-Header.h')))

# --- BreakpointJIT ------------------------------------------------------------------
#
# Deliberately copied by a script phase rather than linked or added to an "Embed
# Frameworks" phase. Two separate reasons, both learned the hard way in AetherPS4:
#
#   * Linking it puts it in the binary's LC_LOAD_DYLIB list, so dyld loads it during
#     launch -- and on a sideloaded signature AMFI rejects an embedded framework that
#     carries entitlements but is not the main binary, killing the process before main()
#     runs. FEXCore dlopen()s it lazily at first use instead (Utils/Allocator.cpp), which
#     never trips that check.
#   * It still has to be physically present in the bundle for that dlopen to find, which
#     nothing else in the build would arrange, since no build input references it.

copy_phase = target.new_shell_script_build_phase('Copy BreakpointJIT.framework')
copy_phase.shell_script = <<~SCRIPT
  set -e
  SOURCE="$SRCROOT/Frameworks/BreakpointJIT.framework"
  DESTINATION="$TARGET_BUILD_DIR/$FRAMEWORKS_FOLDER_PATH"
  if [ ! -d "$SOURCE" ]; then
    echo "error: BreakpointJIT.framework is missing from $SOURCE" >&2
    exit 1
  fi
  mkdir -p "$DESTINATION"
  rm -rf "$DESTINATION/BreakpointJIT.framework"
  cp -R "$SOURCE" "$DESTINATION/"
SCRIPT
copy_phase.input_paths = ['$(SRCROOT)/Frameworks/BreakpointJIT.framework/BreakpointJIT']
copy_phase.output_paths = ['$(TARGET_BUILD_DIR)/$(FRAMEWORKS_FOLDER_PATH)/BreakpointJIT.framework/BreakpointJIT']

# --- Build settings ------------------------------------------------------------------

header_search_paths = [
  '$(inherited)',
  File.join(APP_DIR, 'Sources/Runtime'),
  File.join(FEXCORE_SRC, 'FEXCore/include'),
  File.join(FEXCORE_SRC, 'Source'),
  File.join(FEXCORE_SRC, 'FEXHeaderUtils'),
  File.join(FEXCORE_SRC, 'CodeEmitter'),
  File.join(FEXCORE_SRC, 'External/fmt/include'),
  File.join(FEXCORE_SRC, 'External/unordered_dense/include'),
  File.join(FEXCORE_SRC, 'External/range-v3/include'),
  File.join(FEXCORE_SRC, 'External/vixl/src'),
  File.join(FEXCORE_SRC, 'External/xxhash'),
  File.join(FEXCORE_BUILD, 'include'),
  File.join(FEXCORE_BUILD, 'generated')
]

target.build_configurations.each do |config|
  settings = config.build_settings
  settings['PRODUCT_BUNDLE_IDENTIFIER'] = 'app.fathom.emulator'
  settings['PRODUCT_NAME'] = PROJECT_NAME
  settings['INFOPLIST_FILE'] = 'Info.plist'
  settings['CODE_SIGN_ENTITLEMENTS'] = 'Fathom.entitlements'
  settings['ASSETCATALOG_COMPILER_APPICON_NAME'] = 'AppIcon'
  settings['IPHONEOS_DEPLOYMENT_TARGET'] = DEPLOYMENT_TARGET
  settings['TARGETED_DEVICE_FAMILY'] = '1,2'

  settings['SWIFT_VERSION'] = '5.0'
  settings['SWIFT_OBJC_BRIDGING_HEADER'] = 'Fathom-Bridging-Header.h'

  settings['CLANG_CXX_LANGUAGE_STANDARD'] = 'c++20'
  settings['CLANG_CXX_LIBRARY'] = 'libc++'
  # Deliberately NOT inheriting: Xcode's Debug configuration defines DEBUG=1 project-wide,
  # and FEXCore's LogManager.h declares an enumerator literally named DEBUG (alongside
  # ASSERT, ERROR and INFO). The macro rewrites the enumerator and the header fails to
  # parse, with errors that point inside FEXCore rather than at the definition causing it.
  # Swift's own #if DEBUG is unaffected -- that comes from SWIFT_ACTIVE_COMPILATION_CONDITIONS.
  #
  # META_NO_STD_FORWARD_DECLARATIONS matches how libFEXCore.a itself was compiled
  # (see build-fexcore-ios.sh); disagreeing produces template errors deep inside range-v3.
  settings['GCC_PREPROCESSOR_DEFINITIONS'] = ['META_NO_STD_FORWARD_DECLARATIONS=1',
                                              'ARCHITECTURE_arm64=1']
  settings['HEADER_SEARCH_PATHS'] = header_search_paths
  settings['LIBRARY_SEARCH_PATHS'] = ['$(inherited)', File.join(APP_DIR, 'Libs')]
  settings['FRAMEWORK_SEARCH_PATHS'] = ['$(inherited)', File.join(APP_DIR, 'Frameworks')]

  settings['ARCHS'] = 'arm64'
  settings['VALID_ARCHS'] = 'arm64'
  settings['ONLY_ACTIVE_ARCH'] = 'NO'
  settings['ENABLE_BITCODE'] = 'NO'
  settings['ENABLE_USER_SCRIPT_SANDBOXING'] = 'NO'
  settings['CODE_SIGN_IDENTITY'] = 'Apple Development'
  settings['DEVELOPMENT_TEAM'] = ''
end

project.save
puts "Generated #{PROJECT_PATH}"
puts "  #{libraries.count} static libraries, FEXCore headers from #{FEXCORE_SRC}"
