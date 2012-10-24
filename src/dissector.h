
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
extern "C" {
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
}
#include <glib.h>
#include <string>

class Dissector : node::ObjectWrap {
public:
  static void Init(v8::Handle<v8::Object> target);
  static v8::Handle<v8::Value> New(const v8::Arguments& args);
  ~Dissector();

private:
  Dissector(int linkLayerType);
  static v8::Persistent<v8::FunctionTemplate> s_ct;
  static v8::Handle<v8::Value> dissect(const v8::Arguments& args);
  static v8::Handle<v8::Value> close(const v8::Arguments& args);
  e_prefs* readPrefs(v8::Handle<v8::Value> *error);
  static void treeToObject(proto_node *node, gpointer data);
  static void treeToString(proto_node *node, gpointer data);
  static void xmlTreeToString(proto_node *node, gpointer data);
  static const guint8 *getFieldData(GSList *src_list, field_info *fi);
  static v8::Handle<v8::Value> sliceBuffer(v8::Handle<v8::Object> buffer, int start, int end);
  static const char* getNodeName(proto_node *node, const char *parentName, int *needsFree);
  static const char* fixEscapes(const char* src, char* dest);

  int m_linkLayerType;
  capture_file m_cfile;
  int m_encap;
  nstime_t m_first_ts;
  frame_data *m_prev_dis;
  frame_data *m_prev_cap;
  guint32 m_cum_bytes;
  gint64 m_data_offset;
};

#endif
