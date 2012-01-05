
#ifndef nodeshark_h_
#define nodeshark_h_

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

class NodeShark : node::ObjectWrap {
public:
  static void Init(v8::Handle<v8::Object> target);
  static v8::Handle<v8::Value> New(const v8::Arguments& args);

private:
  static v8::Persistent<v8::FunctionTemplate> s_ct;
  static void openFailureMessage(const char *filename, int err, gboolean for_writing);
  static void failureMessage(const char *msg_format, va_list ap);
  static void readFailureMessage(const char *filename, int err);
  static void writeFailureMessage(const char *filename, int err);
};

#endif
