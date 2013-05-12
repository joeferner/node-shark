# 
#
# linking on Ubuntu 10.04
#  #export WIRESHARK_LIB=/usr/lib/wireshark/
#  export WIRESHARK_LIB=/usr/local/lib/

{
 'conditions': [
  ['OS=="linux"', {
   'variables': {
    'wireshark_include_dir': '/home/rs/Gremlins/wireshark/wireshark-1.8.5/',
    #'wireshark_include_dir': '/home/rs/Gremlins/wireshark/wireshark-1.9.x.backupJDSU/',
    'glib_include_dir': '/usr/include/glib-2.0/',
    'glib_config_include_dir': '/usr/lib/glib-2.0/include/',
    #'wireshark_lib': '/usr/local/lib/',
    'wireshark_lib': '/usr/lib/wireshark/',
   },
  }],
  ['OS=="mac"', {
   'variables': {
    'wireshark_include_dir': '/Users/sommerha/Gremlins/wireshark/wireshark-1.8',
    'glib_include_dir': '/usr/include/glib-2.0/',
    'glib_config_include_dir': '/opt/local/include/glib-2.0',
    'wireshark_lib': '/usr/local/lib/',
   },
  }],
  ['OS=="openbsd"', {
   'variables': {
    # see pkg_info -L tshark19
    'wireshark_include_dir': '/var/pobj/wireshark-1.9.0-SVN-46199/wireshark-1.9.0-SVN-46199',
    'glib_include_dir': '/usr/local/include/glib-2.0/',		# see  pkg_info -L glib2
    'glib_config_include_dir': '/usr/local/lib/glib-2.0/include/',
    'wireshark_lib': '/usr/local/lib/',				# see pkg_info -L tshark19
   },
  }],
  ['OS=="smartos"', {
   'variables': {
    'wireshark_include_dir': '',
    'glib_include_dir': '',
    'glib_config_include_dir': '',
    'wireshark_lib': '',
   },
  }],
 ],
 'targets': [
  {
   'target_name': 'nodeshark',
   'sources': [
    'src/cfile.cpp',
    'src/dissector.cpp',
    'src/dissectorNode.cpp',
    'src/lazyDataSource.cpp',
    'src/lazyDissectorNode.cpp',
    'src/nodeshark.cpp',
    'src/utils.cpp',
   ],
   'defines': [
    'HAVE_CONFIG_H',
   ],
   'include_dirs': [
    '<(wireshark_include_dir)',
    '<(glib_include_dir)',
    '<(glib_config_include_dir)',
   ],
   'link_settings': {
    # library_dirs is not working, use ldflags, see 
    #  https://code.google.com/p/gyp/issues/detail?id=130
    #'library_dirs': [
    # '<(wireshark_lib)',
    #],
    'ldflags': [ 
     '-L<(wireshark_lib)',
    ],
    'libraries': [
     '-lwireshark',
     '-lwiretap',
     '-lwsutil',
    ],
   },
  },
 ],
}
