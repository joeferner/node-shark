
#ifndef _dissector_h_
#define _dissector_h_

#include <v8.h>
#include <node.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>
#include <limits.h>
#include <config.h>
#include <epan/epan.h>
#include <wsutil/privileges.h>
#include <epan/epan_dissect.h>
#include <epan/to_str.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/packet.h>
#include <epan/plugins.h>
#include <cfile.h>
#include <log.h>
#include <glib.h>

class Dissector : node::ObjectWrap {
public:
  static void Init(v8::Handle<v8::Object> target);
  static v8::Handle<v8::Value> New(const v8::Arguments& args);

private:
  static v8::Persistent<v8::FunctionTemplate> s_ct;
  static v8::Handle<v8::Value> dissect(const v8::Arguments& args);

  capture_file m_cfile;
};

#endif
