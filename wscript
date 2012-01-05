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
  conf.env.append_unique('LINKFLAGS', ['-export-dynamic'])

  wireshark_dir = environ.get("WIRESHARK_DIR", "/usr/include/wireshark/")

  wireshark_include = environ.get("WIRESHARK_INCLUDE_DIR", "/usr/include/wireshark/")
  if wireshark_include:
      conf.env.append_unique('CXXFLAGS', [ '-I' + wireshark_include ])

  glib_include = environ.get("GLIB_INCLUDE_DIR", "/usr/include/glib-2.0/")
  if glib_include:
      conf.env.append_unique('CXXFLAGS', [ '-I' + glib_include ])

  glib_config_include = environ.get("GLIB_CONFIG_INCLUDE_DIR", "/usr/lib/i386-linux-gnu/glib-2.0/include/")
  if glib_config_include:
      conf.env.append_unique('CXXFLAGS', [ '-I' + glib_config_include ])

  #conf.env.append_unique('LINKFLAGS', [wireshark_dir + 'epan/libwireshark.la'])
  conf.env.append_unique('LINKFLAGS', ['-lwireshark', '-lwiretap', '-lwsutil'])

def build(bld):
  obj = bld.new_task_gen("cxx", "shlib", "node_addon")
  obj.target = "nodeshark_bindings"
  obj.source = " ".join(["src/nodeshark.cpp", "src/cfile.cpp"])
  obj.includes = "src/"
