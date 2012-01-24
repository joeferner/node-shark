import os
import Options, Utils
from os import unlink, symlink, chdir, environ
from os.path import exists

def set_options(opt):
  opt.tool_options("compiler_cxx")

def configure(conf):
  conf.check_tool("compiler_cxx")
  conf.check_tool("node_addon")

  # Enables all the warnings that are easy to avoid
  conf.env.append_unique('CXXFLAGS', ["-Wall"])
  conf.env.append_unique('CXXFLAGS', ['-Isrc/'])
  conf.env.append_unique('CXXFLAGS', ['-g'])
  conf.env.append_unique('CXXFLAGS', ['-D_FILE_OFFSET_BITS=64'])
  conf.env.append_unique('CXXFLAGS', ['-D_LARGEFILE_SOURCE'])
  conf.env.append_unique('CXXFLAGS', ['-DHAVE_CONFIG_H'])

  wireshark_include = environ.get("WIRESHARK_INCLUDE_DIR")
  if wireshark_include:
      conf.env.append_unique('CXXFLAGS', [ '-I' + wireshark_include ])

  if os.path.exists("/System/Library/Frameworks/"):
    conf.env.append_unique('CXXFLAGS', [ '-I' + wireshark_include + '/macosx-support-libs/glib-2.31.8/' ])
    conf.env.append_unique('CXXFLAGS', [ '-I' + wireshark_include + '/macosx-support-libs/glib-2.31.8/glib/' ])
    conf.env.append_unique('CXXFLAGS', [ '-I' + wireshark_include + '/macosx-support-libs/glib-2.31.8/gmodule/' ])
  else:
    glib_include = environ.get("GLIB_INCLUDE_DIR", "/usr/include/glib-2.0/")
    if glib_include:
        conf.env.append_unique('CXXFLAGS', [ '-I' + glib_include ])

    glib_config_include = environ.get("GLIB_CONFIG_INCLUDE_DIR", "/usr/lib/i386-linux-gnu/glib-2.0/include/")
    if glib_config_include:
        conf.env.append_unique('CXXFLAGS', [ '-I' + glib_config_include ])

  wireshark_lib = environ.get("WIRESHARK_LIB", "/usr/local/lib/")
  if wireshark_lib:
      conf.env.append_unique('LINKFLAGS', [ '-L' + wireshark_lib ])

  conf.env.append_unique('LINKFLAGS', ['-lwireshark', '-lwiretap', '-lwsutil'])

def build(bld):
  obj = bld.new_task_gen("cxx", "shlib", "node_addon")
  obj.target = "nodeshark_bindings"
  obj.source = " ".join([
    "src/nodeshark.cpp",
    "src/dissector.cpp",
    "src/dissectorNode.cpp",
    "src/utils.cpp",
    "src/cfile.cpp",
    "src/lazyDissectorNode.cpp",
    "src/lazyDataSource.cpp"])
  obj.includes = "src/"
