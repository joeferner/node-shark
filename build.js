#!/usr/bin/env node

var path = require('path');
var Builder = require('mnm');
var builder = new Builder();

builder.appendUnique('CXXFLAGS', ['-Isrc/']);
builder.appendUnique('CXXFLAGS', ['-DHAVE_CONFIG_H']);

var wiresharkInclude = process.env["WIRESHARK_INCLUDE_DIR"] || "/usr/include/wireshark/";
builder.failIfNotExists(wiresharkInclude, 'Could not find "%s" check WIRESHARK_INCLUDE_DIR environment variable.');
builder.appendUnique('CXXFLAGS', '-I' + wiresharkInclude);

if(process.platform == 'darwin') {
  builder.appendUnique('CXXFLAGS', [ '-I' + wiresharkInclude + '/macosx-support-libs/glib-2.31.8/' ]);
  builder.appendUnique('CXXFLAGS', [ '-I' + wiresharkInclude + '/macosx-support-libs/glib-2.31.8/glib/' ]);
  builder.appendUnique('CXXFLAGS', [ '-I' + wiresharkInclude + '/macosx-support-libs/glib-2.31.8/gmodule/' ]);
} else {
  var glibInclude = process.env["GLIB_INCLUDE_DIR"] || "/usr/include/glib-2.0/";
  builder.failIfNotExists(glibInclude, 'Could not find "%s" check GLIB_INCLUDE_DIR environment variable.');
  builder.appendUnique('CXXFLAGS', [ '-I' + glibInclude ]);

  var glibConfigInclude = process.env["GLIB_CONFIG_INCLUDE_DIR"] || "/usr/lib/i386-linux-gnu/glib-2.0/include/";
  builder.failIfNotExists(glibConfigInclude, 'Could not find "%s" check GLIB_CONFIG_INCLUDE_DIR environment variable.');
  builder.appendUnique('CXXFLAGS', [ '-I' + glibConfigInclude ]);
}

var wiresharkLib = process.env["WIRESHARK_LIB"] || "/usr/local/lib/";
builder.failIfNotExists(wiresharkLib, 'Could not find "%s" check WIRESHARK_LIB environment variable.');
builder.appendUnique('LINKFLAGS', [ '-L' + wiresharkLib ]);

builder.appendUnique('LINKFLAGS', ['-lwireshark', '-lwiretap', '-lwsutil']);
builder.appendUnique('LINKFLAGS', '-Wl,-rpath,' + wiresharkLib);

builder.target = "nodeshark_bindings";
builder.appendSourceDir('./src');
builder.appendUnique('CXXFLAGS', '-Isrc/');

builder.compileAndLink();
