
#ifndef _node_h_
#define _node_h_

#include <v8.h>
#include <node.h>
#include <config.h>
#include <epan/epan.h>

class DissectorNode : node::ObjectWrap {
public:
  static void Init(v8::Handle<v8::Object> target);
  static v8::Local<v8::Value> New(epan_dissect_t *edt, proto_node *node, v8::Local<v8::Value> result, v8::Local<v8::Object> rawPacket);

private:
  DissectorNode(epan_dissect_t *edt, proto_node *node, v8::Local<v8::Value> result, v8::Local<v8::Object> rawPacket);

  static void NotImplementedSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info);
  static v8::Handle<v8::Value> AbbreviationGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info);
  static v8::Handle<v8::Value> ChildenForEach(const v8::Arguments& args);
  static void ChildrenForEachItem(proto_node *node, gpointer data);
  static int getPositionInPacket(proto_node *node, field_info *fi);
  static const char* fixEscapes(const char* src, char* dest);

  static v8::Persistent<v8::FunctionTemplate> s_ct;
  epan_dissect_t *m_edt;
  proto_node *m_node;
  v8::Local<v8::Value> m_result;
  v8::Local<v8::Object> m_rawPacket;
};

#endif
